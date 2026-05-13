# README_DOCKER

## Purpose

This document explains not only how to run the system with Docker, but also why Docker is used and how the containerized execution works internally.

---

## Why Docker

The system depends on:

- Nmap
- Nuclei
- Python runtime
- FastAPI
- Playwright Chromium
- SQLite storage
- Report and screenshot directories

Running these directly on a host machine introduces:

- dependency conflicts
- inconsistent environments
- OS-specific issues
- browser automation dependency problems

Docker solves this by:

- isolating dependencies
- ensuring reproducibility
- providing an identical runtime across systems
- avoiding unnecessary host-level installation for scanner tools

---

## Architecture (Container Level)

```text
Host Machine
  |
  v
Docker Engine
  |
  v
asm-lite Container
  ├── Python / FastAPI server
  ├── Nmap binary
  ├── Nuclei binary
  ├── Playwright Chromium
  ├── SQLite database path
  ├── Report output directory
  └── Screenshot output directory
```

Most scan operations execute inside the container.

---

## Required Software

Install the following software on the host machine:

- Docker Desktop  
  https://www.docker.com/products/docker-desktop/

- Docker Compose v2 or later  
  Included in Docker Desktop

- Git  
  https://git-scm.com/downloads

Host installation of Python, Nmap, Nuclei, and Playwright is not required when using Docker.

---

## Build Process

Run:

```bash
docker compose up --build
```

### Internals

1. Dockerfile builds the image from the Playwright Python base image.
2. Installs system packages:
   - nmap
   - ca-certificates
   - curl
   - unzip
   - wget
   - git
3. Downloads and installs Nuclei v3.8.0.
4. Installs Python dependencies from `requirements.txt`.
5. Installs Playwright Chromium.
6. Copies project files into `/app`.
7. Creates runtime directories:
   - `/data`
   - `/app/reports`
   - `/app/app/static/screenshots`
8. Starts FastAPI via Uvicorn.

Startup command:

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## docker-compose.yml

Service name:

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
unless-stopped
```

---

## Runtime Flow

1. User accesses the Web UI or API.
2. FastAPI receives the request.
3. Target and scan job data are stored in SQLite.
4. Worker executes the scan pipeline.
5. TCP scan identifies reachable ports.
6. Nmap and Nuclei run inside the container.
7. CVE, EPSS, KEV, web enrichment, and risk scoring are performed.
8. Results are stored in SQLite.
9. Reports and screenshots are written to mounted paths.
10. Output is displayed through the Web UI or returned through API routes.

---

## Access

Web UI:

```text
http://localhost:8000
```

Admin login page:

```text
http://localhost:8000/admin
```

Admin management page:

```text
http://localhost:8000/admin/manage
```

---

## First Login

On first startup, the app creates an admin API key.

Generated file:

```text
ADMIN_API_KEY.txt
```

Use this key to log in through `/admin`.

After logging in as admin, additional API keys can be created or revoked from `/admin/manage`.

---

## Environment Variables

`.env` example:

```env
NVD_API_KEY=
DISCORD_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

Variables used by Docker Compose:

| Variable | Default | Purpose |
|---|---:|---|
| `ASM_ENABLE_SCREENSHOT` | `1` | Enable screenshot collection |
| `DATABASE_PATH` | `/data/asm_lite.db` | SQLite DB path |
| `NVD_API_KEY` | empty | Optional NVD API key |
| `DISCORD_WEBHOOK_URL` | empty | Optional Discord alert webhook |
| `TELEGRAM_BOT_TOKEN` | empty | Optional Telegram bot token |
| `TELEGRAM_CHAT_ID` | empty | Optional Telegram chat ID |

The old example variables below are not used by the current `docker-compose.yml` unless the code is modified to read them:

```env
API_PORT=8000
SCAN_TIMEOUT=60
MAX_THREADS=10
NUCLEI_TEMPLATE_PATH=/templates
```

---

## Installation Check

Verify host tools:

```bash
docker --version
docker compose version
git --version
```

Verify container tools after startup:

```bash
docker compose exec asm-lite python --version
docker compose exec asm-lite nmap --version
docker compose exec asm-lite nuclei -version
docker compose exec asm-lite python -m playwright --version
```

Expected result:

- Docker command prints the installed Docker version.
- Docker Compose command prints Compose v2 or later.
- Python command prints the container Python version.
- Nmap command prints the installed Nmap version.
- Nuclei command prints the installed Nuclei version.
- Playwright command runs normally.

---

## Logs

Follow logs:

```bash
docker compose logs -f asm-lite
```

Show recent logs:

```bash
docker compose logs --tail=100 asm-lite
```

If using raw Docker instead of Compose:

```bash
docker logs -f asm-lite
```

---

## Debugging Inside Container

Open a shell:

```bash
docker compose exec asm-lite bash
```

If using raw Docker:

```bash
docker exec -it asm-lite bash
```

Check tools:

```bash
nmap --version
nuclei -version
python --version
python -m playwright --version
```

Check runtime directories:

```bash
ls -al /data
ls -al /app/reports
ls -al /app/app/static/screenshots
```

---

## Data Persistence

SQLite database:

```text
/data/asm_lite.db
```

Docker volume:

```text
asm_lite_data
```

Reports:

```text
./reports
```

Screenshots:

```text
./app/static/screenshots
```

Back up the database:

```bash
docker compose cp asm-lite:/data/asm_lite.db ./asm_lite_backup.db
```

---

## Rebuild and Reset

Rebuild after code changes:

```bash
docker compose up --build
```

Stop containers:

```bash
docker compose down
```

Full rebuild without cache:

```bash
docker compose build --no-cache
docker compose up
```

Reset including database volume:

```bash
docker compose down -v
docker compose up --build
```

Use `down -v` carefully because it deletes persisted SQLite data.

---

## Common Issues

### Port Conflict

If port `8000` is already in use:

```bat
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

Or change the host-side port:

```yaml
ports:
  - "8080:8000"
```

Then access:

```text
http://localhost:8080
```

---

### Container Not Updating

Run:

```bash
docker compose down
docker compose build --no-cache
docker compose up
```

If database reset is also required:

```bash
docker compose down -v
docker compose up --build
```

---

### Nuclei Template Missing or Nuclei Problem

Check:

```bash
docker compose exec asm-lite nuclei -version
docker compose exec asm-lite which nuclei
```

Update templates if needed:

```bash
docker compose exec asm-lite nuclei -update-templates
```

The current Dockerfile installs the Nuclei binary. Template behavior may depend on Nuclei runtime updates and template cache state.

---

### Nmap Problem

Check:

```bash
docker compose exec asm-lite nmap --version
```

Manual test:

```bash
docker compose exec asm-lite nmap -sV --version-light -p 80,443 example.com
```

---

### Screenshot Problem

Check:

```bash
docker compose exec asm-lite python -m playwright --version
docker compose exec asm-lite ls -al /app/app/static/screenshots
```

Screenshot failures may produce `partial_success` rather than full scan failure.

---

## Best Practice

- Always rebuild after dependency changes.
- Do not install runtime tools manually on the host when using Docker.
- Keep the container environment immutable and reproducible.
- Back up `/data/asm_lite.db` if scan history matters.
- Do not expose admin keys, reports, or screenshots publicly.
- Scan only authorized targets.
