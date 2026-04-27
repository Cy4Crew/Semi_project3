import os
import httpx


async def send_alert(title: str, body: str, severity: str = "info") -> list[str]:
    results = []
    discord_url = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()

    text = f"[{severity.upper()}] {title}\n{body}"

    async with httpx.AsyncClient(timeout=8.0) as client:
        if discord_url:
            try:
                r = await client.post(discord_url, json={"content": text})
                results.append(f"discord:{r.status_code}")
            except Exception as exc:
                results.append(f"discord:error:{exc}")

        if telegram_token and telegram_chat_id:
            try:
                url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
                r = await client.post(url, json={"chat_id": telegram_chat_id, "text": text})
                results.append(f"telegram:{r.status_code}")
            except Exception as exc:
                results.append(f"telegram:error:{exc}")

    return results
