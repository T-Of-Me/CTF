FROM python:3.12-slim@sha256:43e4d702bbfe3bd6d5b743dc571b67c19121302eb172951a9b7b0149783a1c21

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/srv
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /srv

COPY requirements.txt /srv/requirements.txt
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcairo2 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    libxshmfence1 \
    xvfb \
  && rm -rf /var/lib/apt/lists/* \
  && pip install --no-cache-dir -r /srv/requirements.txt \
  && python3 -m playwright install chromium

COPY app /srv/app
COPY scripts /srv/scripts
COPY internal_service /srv/internal_service
COPY docker-entrypoint.sh /srv/docker-entrypoint.sh

RUN chmod +x /srv/docker-entrypoint.sh \
  && mkdir -p /var/app/instance /var/app/uploads /shared/loot \
  && echo "0xfun{fake_flag}" > /flag.txt \
  && useradd -m -u 10001 ctf \
  && chown -R ctf:ctf /srv /var/app /shared /ms-playwright

USER ctf

EXPOSE 5000 7000 9000

CMD ["/srv/docker-entrypoint.sh"]
