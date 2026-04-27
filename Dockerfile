FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    ASM_ENABLE_SCREENSHOT=1 \
    DATABASE_PATH=/data/asm_lite.db

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    ca-certificates \
    curl \
    unzip \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /tmp/nuclei \
    && mv /tmp/nuclei/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei /tmp/nuclei.zip

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /app/requirements.txt \
    && python -m pip install playwright \
    && python -m playwright install chromium

COPY . /app

RUN mkdir -p /data /app/app/static/screenshots /app/reports

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
