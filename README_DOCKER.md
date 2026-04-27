# README_DOCKER

## Purpose

This document explains not only how to run the system with Docker, but
also why Docker is used and how the containerized execution works
internally.

------------------------------------------------------------------------

## Why Docker

The system depends on: - Nmap (requires system-level installation) -
Nuclei (requires templates and binary) - Python runtime (FastAPI)

Running this directly on a host machine introduces: - dependency
conflicts - inconsistent environments - OS-specific issues

Docker solves this by: - isolating dependencies - ensuring
reproducibility - providing identical runtime across systems

------------------------------------------------------------------------

## Architecture (Container Level)

Host Machine\
→ Docker Engine\
→ Container\
├── Python (FastAPI server)\
├── Nmap binary\
├── Nuclei binary\
└── Templates

All scans execute **inside the container**, not on the host.

------------------------------------------------------------------------

## Build Process

docker compose up --build

### Internals

1.  Dockerfile builds base image (python)
2.  Installs:
    -   nmap
    -   nuclei
    -   python dependencies
3.  Copies project files
4.  Starts FastAPI via uvicorn

------------------------------------------------------------------------

## Runtime Flow

1.  User accesses API
2.  FastAPI receives request
3.  Scanner module triggers subprocess
4.  Nmap/Nuclei run inside container
5.  Output processed and returned

------------------------------------------------------------------------

## Access

http://localhost:8000

------------------------------------------------------------------------

## Environment Variables

.env example:

API_PORT=8000\
SCAN_TIMEOUT=60\
MAX_THREADS=10\
NUCLEI_TEMPLATE_PATH=/templates

------------------------------------------------------------------------

## Logs

docker logs -f `<container_name>`{=html}

------------------------------------------------------------------------

## Debugging Inside Container

docker exec -it `<container_name>`{=html} bash

Check tools:

nmap --version\
nuclei -version

------------------------------------------------------------------------

## Common Issues

### Port Conflict

netstat -ano \| findstr :8000\
taskkill /PID `<pid>`{=html} /F

------------------------------------------------------------------------

### Container Not Updating

docker compose down -v\
docker compose up --build

------------------------------------------------------------------------

### Nuclei Template Missing

Ensure template path exists: /root/nuclei-templates

------------------------------------------------------------------------

## Best Practice

-   Always rebuild after dependency changes
-   Do not install tools on host manually
-   Keep container environment immutable
