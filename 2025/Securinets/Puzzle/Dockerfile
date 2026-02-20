FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install debugpy

EXPOSE 5000 5678

CMD ["python", "-Xfrozen_modules=off", "-m", "debugpy", "--listen", "0.0.0.0:5678", "app.py"]
