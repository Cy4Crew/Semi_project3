"""
인증 / 권한 / Rate Limit / 세션 모듈
"""
import secrets
import hashlib
from datetime import datetime
from functools import wraps

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import APIKeyHeader
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.database import get_conn

# ── 세션 설정 ─────────────────────────────────────────────
SECRET_KEY = secrets.token_hex(32)  # 서버 재시작 시 갱신 (운영환경은 환경변수로)
SESSION_COOKIE = "asm_session"
SESSION_MAX_AGE = 3600  # 1시간
_serializer = URLSafeTimedSerializer(SECRET_KEY)

# ── API Key 헤더 ──────────────────────────────────────────
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# ── Rate Limit 설정 ───────────────────────────────────────
RATE_LIMITS = {
    "default": (30, 60),
    "scan":    (3,  60),
    "upload":  (5,  60),
}
_rate_store: dict[str, list[float]] = {}


def _check_rate_limit(key: str, limit: int, window: int) -> bool:
    import time
    now = time.time()
    history = _rate_store.get(key, [])
    history = [t for t in history if now - t < window]
    if len(history) >= limit:
        _rate_store[key] = history
        return False
    history.append(now)
    _rate_store[key] = history
    return True


def rate_limit(limit_type: str = "default"):
    def dependency(request: Request):
        limit, window = RATE_LIMITS.get(limit_type, RATE_LIMITS["default"])
        ip = request.client.host if request.client else "unknown"
        key = f"{limit_type}:{ip}"
        if not _check_rate_limit(key, limit, window):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"요청이 너무 많습니다. {window}초 후 다시 시도하세요.",
                headers={"Retry-After": str(window)},
            )
    return dependency


# ── API Key 관리 ──────────────────────────────────────────
def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def init_auth_table():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            role       TEXT    NOT NULL DEFAULT 'user',
            key_hash   TEXT    NOT NULL UNIQUE,
            created_at TEXT    NOT NULL,
            active     INTEGER NOT NULL DEFAULT 1
        )
    """)
    conn.commit()

    exists = conn.execute("SELECT 1 FROM api_keys WHERE role = 'admin'").fetchone()
    if not exists:
        raw = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO api_keys(name, role, key_hash, created_at) VALUES (?, 'admin', ?, ?)",
            ("default-admin", _hash_key(raw), datetime.utcnow().isoformat()),
        )
        conn.commit()
        with open("ADMIN_API_KEY.txt", "w") as f:
            f.write(f"Admin API Key: {raw}\n")
            f.write("이 파일을 안전한 곳에 보관하고 삭제하세요.\n")
        print(f"\n[AUTH] Admin API Key 생성됨: {raw}")
        print("[AUTH] ADMIN_API_KEY.txt 파일에 저장됨\n")
    conn.close()


def _lookup_key(raw: str):
    hashed = _hash_key(raw)
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM api_keys WHERE key_hash = ? AND active = 1", (hashed,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def verify_api_key(api_key: str = Depends(API_KEY_HEADER)) -> dict:
    if not api_key:
        raise HTTPException(status_code=401, detail="API Key가 필요합니다.")
    user = _lookup_key(api_key)
    if not user:
        raise HTTPException(status_code=403, detail="유효하지 않은 API Key입니다.")
    return user


def require_admin(user: dict = Depends(verify_api_key)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")
    return user


def issue_api_key(name: str, role: str = "user") -> str:
    raw = secrets.token_urlsafe(32)
    hashed = _hash_key(raw)
    conn = get_conn()
    conn.execute(
        "INSERT INTO api_keys(name, role, key_hash, created_at) VALUES (?, ?, ?, ?)",
        (name, role, hashed, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()
    return raw


def revoke_api_key(key_id: int):
    conn = get_conn()
    conn.execute("UPDATE api_keys SET active = 0 WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()


# ── 세션 ─────────────────────────────────────────────────
def create_session(response, user: dict):
    """로그인 성공 후 세션 쿠키 발급"""
    payload = {"id": user["id"], "name": user["name"], "role": user["role"]}
    token = _serializer.dumps(payload)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
    )


def get_session(request: Request):
    """세션 쿠키 → 유저 정보 반환 (없으면 None)"""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        payload = _serializer.loads(token, max_age=SESSION_MAX_AGE)
        return payload
    except (BadSignature, SignatureExpired):
        return None


def require_session(request: Request) -> dict:
    """로그인 필요 의존성 - 없으면 /login으로 리다이렉트"""
    user = get_session(request)
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user


def require_admin_session(request: Request) -> dict:
    """관리자 세션 필요"""
    user = require_session(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")
    return user


# ── 스캔 제한 ─────────────────────────────────────────────
MAX_TARGETS_PER_SCAN = 10
MAX_TOTAL_TARGETS = 100


def check_total_target_limit():
    conn = get_conn()
    count = conn.execute("SELECT COUNT(*) c FROM targets").fetchone()["c"]
    conn.close()
    if count >= MAX_TOTAL_TARGETS:
        raise HTTPException(400, f"최대 {MAX_TOTAL_TARGETS}개의 타겟만 등록 가능합니다.")