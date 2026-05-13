# README_DOCKER

This document explains how to run ASM-Lite / Semi_project3 with Docker Compose.

The Docker environment packages Python, Nmap, Nuclei, and Playwright Chromium inside the container to reduce host-specific dependency issues.

---

## Why Docker Is Used

ASM-Lite is not just a Python web application. It also runs external security tools and browser automation.

Required components:

- FastAPI Python server
- Nmap
- Nuclei
- Playwright Chromium
- SQLite database
- Report output directory
- Screenshot output directory

Installing these directly on the host can create OS-specific dependency conflicts. Docker provides a reproducible runtime environment.

---

## Dockerfile Overview

The current Dockerfile builds the image in this order:

```text
mcr.microsoft.com/playwright/python:v1.48.0-jammy
        |
        +--> Set Python environment variables
        +--> Install apt packages
        |       - nmap
        |       - ca-certificates
        |       - curl
        |       - unzip
        |       - wget
        |       - git
        |
        +--> Download and install Nuclei v3.8.0
        +--> Install requirements.txt
        +--> Install Playwright Chromium
        +--> Copy project files
        +--> Create /data, screenshots, reports directories
        +--> Run uvicorn app.main:app
```

Container startup command:

```text
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## docker-compose.yml Overview

Compose service name:

```text
asm-lite
```

Container name:

```text
asm-lite
```

Port mapping:

```text
8000:8000
```

Volumes:

```text
asm_lite_data:/data
./reports:/app/reports
./app/static/screenshots:/app/app/static/screenshots
```

Restart policy:

```text
restart: unless-stopped
```

---

## Quick Start

Run from the project root:

```bash
docker compose up --build
```

Run in the background:

```bash
docker compose up -d --build
```

Open:

```text
http://localhost:8000
```

---

## First Login

On first startup, the application creates an admin API key.

Generated file:

```text
ADMIN_API_KEY.txt
```

Use this key to log in at:

```text
http://localhost:8000/admin
```

Admin management page:

```text
http://localhost:8000/admin/manage
```

The admin page can create and revoke additional API keys.

---

## Environment Variables

The following variables are passed through `docker-compose.yml`.

| Variable | Default | Purpose |
|---|---:|---|
| `ASM_ENABLE_SCREENSHOT` | `1` | Enable screenshot collection |
| `DATABASE_PATH` | `/data/asm_lite.db` | SQLite DB path |
| `NVD_API_KEY` | empty | Optional NVD API key |
| `DISCORD_WEBHOOK_URL` | empty | Optional Discord alert webhook |
| `TELEGRAM_BOT_TOKEN` | empty | Optional Telegram bot token |
| `TELEGRAM_CHAT_ID` | empty | Optional Telegram chat ID |

You can create a `.env` file for optional values.

```env
NVD_API_KEY=
DISCORD_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

---

## Container Status

Check running containers:

```bash
docker compose ps
```

Follow logs:

```bash
docker compose logs -f asm-lite
```

Show recent logs:

```bash
docker compose logs --tail=100 asm-lite
```

Open a shell inside the container:

```bash
docker compose exec asm-lite bash
```

---

## Verify Installed Tools

Run inside the container:

```bash
nmap --version
nuclei -version
python --version
python -m playwright --version
```

Verify the FastAPI app import:

```bash
python -c "from app.main import app; print(app.title)"
```

---

## Data Locations

SQLite DB:

```text
/data/asm_lite.db
```

Docker volume:

```text
asm_lite_data
```

Report files:

```text
./reports
```

Screenshots:

```text
./app/static/screenshots
```

---

## Rebuild

Normal rebuild after code changes:

```bash
docker compose up --build
```

Remove the container and rebuild:

```bash
docker compose down
docker compose up --build
```

Remove the volume and fully reset data:

```bash
docker compose down -v
docker compose up --build
```

`docker compose down -v` deletes the SQLite database volume. Use it only when data reset is intended.

---

## Port Conflict

If port `8000` is already in use, the container will fail to start.

Check on Windows:

```bat
netstat -ano | findstr :8000
```

Kill the process:

```bat
taskkill /PID <PID> /F
```

Or change the host port in `docker-compose.yml`:

```yaml
ports:
  - "8080:8000"
```

Then open:

```text
http://localhost:8080
```

---

## Nuclei Troubleshooting

Check Nuclei:

```bash
docker compose exec asm-lite nuclei -version
```

Check binary path:

```bash
docker compose exec asm-lite which nuclei
```

Depending on the environment, templates may need to be updated:

```bash
docker compose exec asm-lite nuclei -update-templates
```

---

## Nmap Troubleshooting

Check Nmap:

```bash
docker compose exec asm-lite nmap --version
```

Run a direct test from inside the container:

```bash
docker compose exec asm-lite nmap -sV --version-light -p 80,443 example.com
```

---

## Playwright / Screenshot Troubleshooting

Verify Chromium installation:

```bash
docker compose exec asm-lite python -m playwright install chromium
```

Check screenshot directory:

```bash
docker compose exec asm-lite ls -al /app/app/static/screenshots
```

Check host mount:

```bash
ls app/static/screenshots
```

---

## Database Check

Check DB files inside the container:

```bash
docker compose exec asm-lite ls -al /data
```

SQLite file:

```text
/data/asm_lite.db
```

Back up the database:

```bash
docker compose cp asm-lite:/data/asm_lite.db ./asm_lite_backup.db
```

---

## Common Issues

### 1. Port 8000 is already allocated

Symptom:

```text
Bind for 0.0.0.0:8000 failed: port is already allocated
```

Fix:

```bat
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

Or change the Compose port mapping.

---

### 2. Admin key cannot be found

Check logs:

```bash
docker compose logs asm-lite
```

Check file:

```bash
ls ADMIN_API_KEY.txt
```

Check inside the container:

```bash
docker compose exec asm-lite ls -al
```

---

### 3. Scan completed but screenshots failed

Possible causes:

- Target web service is unreachable
- TLS error
- Playwright timeout
- The target is not a web service

In this case, the scan may be marked as `partial_success`.

---

### 4. NVD response is slow

Set `NVD_API_KEY` to reduce API rate-limit issues.

```env
NVD_API_KEY=<your_key>
```

---

### 5. Code changes are not reflected

This may be an image cache issue.

```bash
docker compose down
docker compose build --no-cache
docker compose up
```

---

## Operational Rules

- Rebuild with `docker compose up --build` after code changes.
- Use `docker compose down -v` only when database reset is intended.
- Back up `/data/asm_lite.db` regularly if scan history matters.
- Scan only assets that are explicitly authorized.
