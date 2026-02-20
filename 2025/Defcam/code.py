#!/usr/bin/env python3

import time
import sys
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import urllib.parse
import threading

class AdminBotTungPhan:
    def __init__(self, base_url="http://localhost:3434")
        self.base_url = base_url
        self.driver = None
        self.setup_driver()

if __name__ ==  "__main__":
    