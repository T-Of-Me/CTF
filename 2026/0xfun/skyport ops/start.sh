#!/bin/bash
set -e

cat > /tmp/start_gateway.py << 'PYEOF'
from lib_gateway_port import SecurityGateway
import threading
import time

def start_gateway():
    gateway = SecurityGateway()
    gateway.start()

gateway_thread = threading.Thread(target=start_gateway, daemon=True)
gateway_thread.start()
time.sleep(999999)
PYEOF

python3 /tmp/start_gateway.py &
sleep 2
exec su -s /bin/bash skyport -c "/app/venv/bin/python3 -m hypercorn /app/app:app --bind 127.0.0.1:5000 --workers 2 --worker-class asyncio --max-requests 100"
