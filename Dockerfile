# syntax=docker/dockerfile:1

FROM python:3.11-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    rustc \
    cargo \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY requirements.txt ./
RUN pip install --upgrade pip setuptools wheel
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --prefix=/install --no-cache-dir -e .


FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/lumen/.local/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libxml2 \
    libxslt1.1 \
    libssl3 \
    libffi8 \
    nmap \
    nikto \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash lumen
WORKDIR /home/lumen/app

COPY --from=builder /install /usr/local
COPY --chown=lumen:lumen . .

USER lumen

ENTRYPOINT ["lumen"]
CMD ["--help"]
