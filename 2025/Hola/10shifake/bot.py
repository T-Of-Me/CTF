from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import jwt
import os

PORT = 5000
SECRET_KEY = os.environ.get("SECRET_KEY", "test")

class Bot:
    def __init__(self):
        pass  

    def visit(self, url):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--window-size=1920x1080")
        chrome_options.add_argument("--disable-background-networking")
        chrome_options.add_argument("--disable-software-rasterizer")

        driver = webdriver.Chrome(options=chrome_options)
        try:
            token = jwt.encode({"username": "admin"}, SECRET_KEY, algorithm="HS256")
            driver.get(f"http://127.0.0.1:{PORT}/")  
            driver.add_cookie({
                "name": "token",
                "value": token,
                "httponly": False
            })
            driver.get(url)
            time.sleep(1)  
            driver.refresh()
            print(f"[+] Visited {url}")
        except Exception as e:
            print(f"[!] Error visiting {url}: {e}")
        finally:
            driver.quit()

