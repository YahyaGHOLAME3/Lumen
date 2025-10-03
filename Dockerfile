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

# Fetch Nikto once during build stage so runtime image can use it without git
RUN git clone --depth=1 https://github.com/sullo/nikto.git /opt/nikto \
    && rm -rf /opt/nikto/.git


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
    openssl \
    curl \
    perl \
    libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash lumen
WORKDIR /home/lumen/app

COPY --from=builder /install /usr/local
COPY --from=builder /opt/nikto /opt/nikto
COPY --chown=lumen:lumen . .

# Provide nikto executable wrapper
RUN printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto

USER lumen

ENTRYPOINT ["lumen"]
CMD ["--help"]
