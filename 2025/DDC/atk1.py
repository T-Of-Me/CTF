
import requests
import random
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

options = Options()
options.add_argument('--headless')  # Chạy không hiện cửa sổ trình duyệt
driver = webdriver.Chrome(options=options)

driver.get('https://mta.edu.vn/')
# theem dong ho hien thi dang chay 

#print(driver.page_source)  # In ra nội dung HTML sau khi JavaScript đã chạy
# viet vao file 
#with open("mta.html","w") as f:
#    f.write(driver.page_source)
print("Da luu vao file mta.html")


# thu het link trong the href 
from bs4 import BeautifulSoup
with open("mta.html", "r", encoding="utf-8") as f:
    html = f.read()
soup = BeautifulSoup(html, 'html.parser')
links = soup.find_all('a')
for link in links:
    href = link.get('href')
    if href:
        print(href)
        # Neu trung thi khong luu nua
        if  href in "links.txt" :
            continue
        else :
            with open("links.txt","a",encoding="utf-8") as f:
                f.write(href+"\n")


