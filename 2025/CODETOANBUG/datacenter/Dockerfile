FROM python:3.9

WORKDIR /app

COPY requirements.txt .
COPY app.py .
COPY flag.txt .

RUN mkdir static templates

COPY static/style.css static/style.css

COPY templates/index.html templates/index.html

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 4015

CMD ["python", "app.py"]

