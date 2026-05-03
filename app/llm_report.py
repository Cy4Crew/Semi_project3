# app/llm_report.py

import requests
import json

OLLAMA_URL = "http://host.docker.internal:11434/api/generate"
MODEL = "gemma3:4b"


def build_scan_data(scan, ports, findings, changes, tech_rows, recommendations):
    return {
        "target": scan["value"],
        "label": scan["label"],
        "risk_score": scan["risk_score"] if "risk_score" in scan.keys() else None,
        "status": scan["status"] if "status" in scan.keys() else None,
        "open_ports": [
            {
                "port": p["port"],
                "protocol": p["protocol"] if "protocol" in p.keys() else "",
                "service": p["service"] if "service" in p.keys() else "",
                "product": p["product"] if "product" in p.keys() else "",
                "version": p["version"] if "version" in p.keys() else "",
            }
            for p in ports
        ],
        "findings": [
            {
                "severity": f["severity"] if "severity" in f.keys() else "",
                "template": f["template"] if "template" in f.keys() else "",
                "name": f["name"] if "name" in f.keys() else "",
                "description": f["description"] if "description" in f.keys() else "",
            }
            for f in findings
        ],
        "changes": [
            {
                "type": c["change_type"] if "change_type" in c.keys() else "",
                "description": c["description"] if "description" in c.keys() else "",
            }
            for c in changes
        ],
        "technologies": [
            {
                "technology": t["technology"] if "technology" in t.keys() else "",
                "evidence": t["evidence"] if "evidence" in t.keys() else "",
            }
            for t in tech_rows
        ],
        "recommendations": [
            {
                "severity": r["severity"] if "severity" in r.keys() else "",
                "title": r["title"] if "title" in r.keys() else "",
                "body": r["body"] if "body" in r.keys() else "",
            }
            for r in recommendations
        ],
    }


def generate_asm_report(scan, ports, findings, changes, tech_rows, recommendations):
    scan_data = build_scan_data(scan, ports, findings, changes, tech_rows, recommendations)

    prompt = f"""
너는 ASM(Attack Surface Management) 보안 분석가다.

아래 데이터는 특정 자산에 대해 수행된 서비스 포트 스캔 결과다.
데이터에 없는 내용은 추측하지 말고, 발견된 사실만 기반으로 작성하라.

중요 규칙:
- CVE, CVSS, EPSS 정보가 없으면 절대 언급하지 마라.
- 보안 용어(HTTP, SSH, XSS 등)는 영어 그대로 사용하라.
- 출력은 반드시 한국어로 작성하라.
- 과장하지 말고 운영자가 이해할 수 있게 작성하라.

출력 형식:

## 🔍 ASM 인사이트 요약
3~4문장

## 📊 주요 변화
- 신규 열린 포트:
- 닫힌 포트:
- 서비스 변경:
- 신규/유지 취약점:

## ⚠️ 위험 해석
Low / Medium / High 중 하나로 설명하고 이유 작성

## 🛠️ 운영자 권장 조치
1.
2.
3.

스캔 데이터:
{json.dumps(scan_data, ensure_ascii=False, indent=2)}
"""

    res = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
        },
        timeout=120,
    )
    res.raise_for_status()
    return res.json().get("response", "")
