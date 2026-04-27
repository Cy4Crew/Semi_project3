Semi_project3 README_DOCKER
===========================

1. Purpose
----------

This document explains how to run Semi_project3 with Docker.

Docker is the recommended execution method because it provides a stable and reproducible environment.

The Docker version includes:

- Python runtime
- FastAPI
- Uvicorn
- Nmap
- Nuclei
- Playwright
- Chromium
- SQLite support


2. Why Docker Is Recommended
----------------------------

Windows local execution can work, but security tools often depend on system-level binaries.

Common Windows issues:

- Nmap PATH issue
- Nuclei PATH issue
- Playwright subprocess issue
- Python version mismatch
- SQLite file path inconsistency

Docker reduces these problems by fixing the runtime environment.


3. Requirements
---------------

Install:

- Docker Desktop
- Docker Compose v2

Check installation:

    docker --version

    docker compose version


4. Start with Script
--------------------

Run:

    run_docker.bat

This script should:

1. Build the Docker image
2. Start the container
3. Open or display the dashboard URL

Dashboard:

    http://127.0.0.1:8000


5. Start Manually
-----------------

From the project folder:

    docker compose build

    docker compose up -d

Open:

    http://127.0.0.1:8000


6. Stop
-------

Using script:

    stop_docker.bat

Manual:

    docker compose down


7. View Logs
------------

Using script:

    logs_docker.bat

Manual:

    docker compose logs -f asm-lite


8. Rebuild
----------

If files are changed:

    docker compose build --no-cache

    docker compose up -d

If only restarting:

    docker compose restart


9. Port Mapping
---------------

Default:

    Host port:      8000
    Container port: 8000

Browser URL:

    http://127.0.0.1:8000

If port 8000 is already in use, change docker-compose.yml:

    ports:
      - "8088:8000"

Then open:

    http://127.0.0.1:8088


10. Scanning Local Host Services from Docker
--------------------------------------------

Inside Docker, 127.0.0.1 means the container itself.

If you want to scan a service running on the Windows host, use:

    host.docker.internal

Do not include a port.

Correct:

    host.docker.internal

Wrong:

    host.docker.internal:8080


11. Screenshot Capture
----------------------

Docker is better for screenshot capture because Chromium runs in a Linux container.

Docker environment should use:

    ASM_ENABLE_SCREENSHOT=1

If screenshot capture fails, Semi_project3 creates HTML fallback evidence.

Possible evidence outputs:

    PNG screenshot
    HTML evidence fallback


12. Environment Variables
-------------------------

Optional .env file:

    NVD_API_KEY=
    DISCORD_WEBHOOK_URL=
    TELEGRAM_BOT_TOKEN=
    TELEGRAM_CHAT_ID=

Explanation:

    NVD_API_KEY
        Used for optional CVE lookup.

    DISCORD_WEBHOOK_URL
        Used for optional Discord alert.

    TELEGRAM_BOT_TOKEN
        Used for optional Telegram alert.

    TELEGRAM_CHAT_ID
        Telegram target chat ID.


13. Data Persistence
--------------------

Docker Compose can persist:

- SQLite database
- Reports
- Screenshots

Typical paths:

    /data/asm_lite.db
    /app/reports
    /app/app/static/screenshots

If you remove the volume, scan history may be deleted.


14. Clean Reset
---------------

To remove containers:

    docker compose down

To remove containers and volumes:

    docker compose down -v

Use volume deletion only if you want a clean database.


15. Useful Docker Commands
--------------------------

Show containers:

    docker ps

Enter container:

    docker compose exec asm-lite bash

Check Nmap:

    docker compose exec asm-lite nmap --version

Check Nuclei:

    docker compose exec asm-lite nuclei -version

Check Python:

    docker compose exec asm-lite python --version

View logs:

    docker compose logs -f asm-lite


16. Recommended Demo Procedure
------------------------------

Before presentation:

1. Start Docker Desktop
2. Run run_docker.bat
3. Open dashboard
4. Add scanme.nmap.org
5. Run scan once before demo
6. Confirm screenshot/evidence is visible
7. Confirm port detail pages open

During presentation:

1. Explain target input
2. Run scan
3. Show open ports
4. Show service/version detection
5. Show recommendations
6. Click port detail
7. Show report


17. Troubleshooting
-------------------

Problem:

    Dashboard does not open.

Check:

    docker ps
    docker compose logs -f asm-lite

Problem:

    Port already in use.

Fix:

    Change host port mapping.

Problem:

    Screenshot missing.

Fix:

    Check logs. HTML fallback evidence is acceptable.

Problem:

    Nuclei templates outdated.

Fix:

    Rebuild or run update command inside container if configured.

Problem:

    Target does not resolve.

Fix:

    Enter hostname only. Do not include http:// or port number.
