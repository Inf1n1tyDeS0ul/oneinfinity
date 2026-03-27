
import asyncio
import json
from playwright.async_api import async_playwright
from pathlib import Path

TARGET = "https://app.test.12build.com"
CRED_A = ("intigriti-pentest+62a@12build.com", "518FE8195E85E84F")
CRED_B = ("intigriti-pentest+62b@12build.com", "031F785A22EFE0FF")

async def login(page, email, password):
    print(f"[*] Attempting login for {email}...")
    await page.goto(f"{TARGET}/login")
    await page.wait_for_selector('[data-testid="login-username-input"]')
    await page.fill('[data-testid="login-username-input"]', email)
    await page.fill('[data-testid="login-password-input"]', password)
    await page.click('[data-testid="submit-login-btn"]')
    
    # Wait for successful login (dashboard or company-select)
    try:
        await page.wait_for_url("**/dashboard**", timeout=10000)
        print(f"[+] Login successful for {email}")
    except:
        try:
            await page.wait_for_url("**/company-select**", timeout=5000)
            print(f"[+] Login successful for {email} (company-select)")
        except:
            print(f"[-] Login failed or timed out for {email}")
            return None
    
    cookies = await page.context.cookies()
    cookie_dict = {c['name']: c['value'] for c in cookies}
    return cookie_dict

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        
        # User A
        context_a = await browser.new_context()
        page_a = await context_a.new_page()
        cookies_a = await login(page_a, CRED_A[0], CRED_A[1])
        
        # User B
        context_b = await browser.new_context()
        page_b = await context_b.new_page()
        cookies_b = await login(page_b, CRED_B[0], CRED_B[1])
        
        if cookies_a and cookies_b:
            auth_data = {
                "user_a": {"email": CRED_A[0], "cookies": cookies_a},
                "user_b": {"email": CRED_B[0], "cookies": cookies_b}
            }
            output_path = Path("/Users/devendrayadav/.gemini/tmp/oneinfinity/workspaces/12build/auth_sessions.json")
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(auth_data, f, indent=2)
            print(f"[+] Auth sessions saved to {output_path}")
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
