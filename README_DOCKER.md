## Docker Run

Recommended for stable Playwright screenshot capture.

### Requirements

- Docker Desktop
- Docker Compose v2

### Start

```bat
run_docker.bat
```

or:

```bat
docker compose build
docker compose up -d
```

Open:

```text
http://127.0.0.1:8000
```

### Stop

```bat
stop_docker.bat
```

or:

```bat
docker compose down
```

### Logs

```bat
logs_docker.bat
```

or:

```bat
docker compose logs -f asm-lite
```

### Docker Features

- Python version fixed inside container
- Nmap installed inside container
- Nuclei installed inside container
- Playwright Chromium installed inside container
- Screenshots enabled by default
- SQLite data persisted in Docker volume
- Reports and screenshots mounted to local folders

### Optional Environment Variables

Create `.env` next to `docker-compose.yml` if needed:

```env
NVD_API_KEY=
DISCORD_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```
