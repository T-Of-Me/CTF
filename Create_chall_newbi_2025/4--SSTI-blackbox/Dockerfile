FROM python:3.9-slim

WORKDIR /app

# Copy requirements và install trước
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY app.py .
COPY templates/ templates/

# Tạo flag
RUN echo "CTF{sst1_byp4ss_bl4ckl1st_l1k3_4_pr0}" > /flag.txt
RUN chmod 444 /flag.txt

EXPOSE 5000

CMD ["python", "app.py"]
 