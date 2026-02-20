FROM python:3.11-bullseye AS app-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

COPY flag_reader.c /build/
RUN gcc -o /build/flag /build/flag_reader.c

FROM python:3.11-bullseye

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir lib-gateway-port==1.2.8 && \
    python3 -m venv --system-site-packages /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY --from=app-builder /build/flag /flag
RUN chown root:root /flag && chmod 4755 /flag

RUN echo "0xfun{fake_flag}" > /root/flag.txt && \
    chmod 600 /root/flag.txt && \
    useradd -m -s /bin/bash skyport && \
    mkdir -p /tmp/skyport_uploads && \
    chown -R skyport:skyport /tmp/skyport_uploads

COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 9000
CMD ["/bin/bash", "/start.sh"]
