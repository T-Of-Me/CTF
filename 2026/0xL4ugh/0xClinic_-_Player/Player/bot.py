import asyncio
from pyppeteer import launch
import time
from utils.auth import create_token
import sys
from os import environ

stdout = sys.stdout
stderr = sys.stderr

async def run_health_check(DOCTOR_SESSION, ADMIN_KEY):
    browser = await launch(
        headless=True,
        args=[
            '--no-sandbox',
            '--disable-dev-shm-usage',
            '--disable-gpu',
        ],
        ignoreHTTPSErrors=True,
    )
    
    page = await browser.newPage()
    await page.setCookie({
        'name': 'ADMIN_KEY',
        'value': ADMIN_KEY,
        'domain': 'localhost',
        'path': '/',
        'httpOnly': True,
        'secure': False,
        'sameSite': 'Lax'})
    
    await page.setCookie({
        'name': 'auth',
        'value': DOCTOR_SESSION,
        'domain': 'localhost',
        'path': '/',
        'httpOnly': True,
        'secure': False,
        'sameSite': 'Lax'
    })
    await page.setRequestInterception(True)

    async def intercept(request):
        url = request.url
        if (
            url.startswith("http://localhost/")
        ):
            await request.continue_()
        else:
            await request.abort()

    page.on("request", lambda req: asyncio.ensure_future(intercept(req)))

    try:
        response = await page.goto('http://localhost/api/health', {'waitUntil': 'load', 'timeout': 15000})
        
        if response.status == 200:
            print("[*] Health check page loaded successfully.", flush=True)
        else:
            print(f"[!] Failed to load health check page. Status: {response.status}", flush=True)
    
    except Exception as e:
        print(f"[!] Error during navigation: {e}", flush=True)
        print(f"[!] Error type: {type(e).__name__}", flush=True)
        
    await asyncio.sleep(3)
    await browser.close()

async def main():
    print("[*] Generating doctor session token...", flush=True)
    DOCTOR_SESSION = create_token({
        "user_id": "D001", "username": "HealthCheckBot", "role": "doctor", "verified": True},sys.argv[1])

    try:
        ADMIN_KEY = environ["ADMIN_KEY"]
    except KeyError:
        exit("[!] ADMIN_KEY not set in environment variables.")

    print("[*] ADMIN_KEY:", ADMIN_KEY, flush=True)

    print(f"\n[*] Running health check at {time.strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
    try:
        await run_health_check(DOCTOR_SESSION, ADMIN_KEY)
    except Exception as e:
        print(f"[!] Health check failed: {e}", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
    sys.exit(0)