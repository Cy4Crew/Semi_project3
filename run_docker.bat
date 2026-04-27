@echo off
chcp 65001 >nul
title ASM-Lite Docker Run

cd /d %~dp0

echo [1/3] Building Docker image...
docker compose build

echo [2/3] Starting ASM-Lite...
docker compose up -d

echo [3/3] Opening dashboard...
start http://127.0.0.1:8000

echo.
echo ASM-Lite is running at http://127.0.0.1:8000
echo To stop: docker compose down
pause
