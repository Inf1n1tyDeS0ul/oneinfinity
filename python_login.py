
import asyncio
import json
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        async def handle_request(request):
            if request.method == "POST":
                print(f"POST {request.url}")
                print(f"Payload: {request.post_data}")

        async def handle_response(response):
            if "login" in response.url or "token" in response.url:
                print(f"Response {response.url}: {response.status}")
                try:
                    body = await response.text()
                    print(f"Body: {body[:200]}")
                except:
                    pass

        page.on("request", handle_request)
        page.on("response", handle_response)

        print("[*] Going to login page...")
        await page.goto("https://app.test.12build.com/login")
        
        print("[*] Waiting for form...")
        await page.wait_for_selector('[data-testid="login-username-input"]')
        
        print("[*] Filling form...")
        await page.fill('[data-testid="login-username-input"]', "intigriti-pentest+62a@12build.com")
        await page.fill('[data-testid="login-password-input"]', "518FE8195E85E84F")
        
        print("[*] Submitting...")
        await page.click('[data-testid="submit-login-btn"]')
        
        print("[*] Waiting for redirection...")
        await asyncio.sleep(10)

        cookies = await context.cookies()
        print("COOKIES:", json.dumps(cookies, indent=2))

        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
