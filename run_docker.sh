#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
docker compose build
docker compose up -d
echo "ASM-Lite is running at http://127.0.0.1:8000"
