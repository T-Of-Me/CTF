FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash oim && \
    chown -R oim:oim /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Create flag with restricted permissions
RUN echo "FLAG{CVE_2025_61757_0r4cl3_1d3nt1ty_pwn3d}" > /flag.txt && \
    chown oim:oim /flag.txt && \
    chmod 400 /flag.txt

# Set proper ownership
RUN chown -R oim:oim /app

ENV FLAG="FLAG{CVE_2025_61757_0r4cl3_1d3nt1ty_pwn3d}"

EXPOSE 14000

# Run as non-root user
USER oim

CMD ["python", "app.py"]
