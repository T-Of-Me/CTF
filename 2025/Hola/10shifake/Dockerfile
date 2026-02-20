FROM ghcr.io/n1ght-f4ll/ehctf/python:alpine

RUN mkdir -p /app && \
    adduser -D -G www-data -s /bin/ash -h /app www-data

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chmod=500 --chown=www-data:www-data app.py database.py bot.py /app/
COPY templates/ /app/templates/
COPY static/ /app/static/
COPY --chmod=500 --chown=www-data:www-data init.sh /etc/init.sh
RUN sed -i 's/\r//' /etc/init.sh

USER www-data
ENTRYPOINT ["/bin/sh", "/etc/init.sh"]
