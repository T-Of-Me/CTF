FROM python:3.11-slim

RUN pip install --upgrade pip
RUN pip install -U fastapi uvicorn[standard] Jinja2 python-multipart PyJWT regex
RUN pip install httptools pyppeteer timeout_decorator

RUN useradd -m -u 1000 appuser


RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx supervisor \
    libnspr4 \
    libnss3 \
    libdbus-1-3 \
    libatk1.0-0t64 \
    libatk-bridge2.0-0t64 \
    libatspi2.0-0t64 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libxkbcommon0 \
    libasound2t64 \
    libx11-xcb1 \
    libxcb-dri3-0 \
    libdrm2 \
    libglib2.0-0 \
    libcups2 \
    libpango-1.0-0 \
    libcairo2 \
    libgtk-3-0 \
    wget \
    ca-certificates \
    fonts-liberation \
    openssl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app/

COPY . .

RUN rm -f /app/Dockerfile

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

COPY nginx.conf /etc/nginx/nginx.conf

RUN chown -R appuser:appuser /app/

USER appuser
RUN unset FLAG
ENV PYPPETEER_HOME=/home/appuser/.local/share/pyppeteer
RUN pyppeteer-install

USER root

EXPOSE 80

CMD ["supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
