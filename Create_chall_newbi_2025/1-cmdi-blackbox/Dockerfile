FROM python:3.9-slim

WORKDIR /app

RUN pip install flask

COPY app.py .
COPY flag.txt /flag.txt

RUN chmod 444 /flag.txt

EXPOSE 5000

CMD ["python", "app.py"]