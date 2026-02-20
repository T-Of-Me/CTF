FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV NODE_ENV=production

RUN apt-get update && \
    apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    curl \
    wget \
    ca-certificates \
    fontconfig \
    libfreetype6 \
    libx11-6 \
    libxcb1 \
    libxext6 \
    libxrender1 \
    xfonts-75dpi \
    xfonts-base \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs && echo "bXVzaHJvb20gbG92ZXMgeW91Cg=="

RUN wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.jammy_amd64.deb -O /tmp/wkhtmltox.deb && \
    dpkg -i /tmp/wkhtmltox.deb || apt-get install -f -y && \
    rm /tmp/wkhtmltox.deb

WORKDIR /app

COPY internal /app/internal
RUN python3 -m venv /app/internal/venv && \
    /app/internal/venv/bin/pip install --no-cache-dir -r /app/internal/requirements.txt

COPY prod /app/prod
WORKDIR /app/prod
RUN npm ci && npm run build

RUN echo "0xL4ugh{REDACTED}" > /flag

WORKDIR /app
EXPOSE 3000

CMD bash -c "\
  /app/internal/venv/bin/python /app/internal/app.py & \
  npm --prefix /app/prod start \
"
