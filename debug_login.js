
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  page.on('request', request => {
    if (request.method() === 'POST') {
      console.log(`POST ${request.url()}`);
      console.log(`Payload: ${request.postData()}`);
    }
  });

  page.on('response', response => {
    if (response.url().includes('login') || response.url().includes('token')) {
      console.log(`Response ${response.url()}: ${response.status()}`);
    }
  });

  await page.goto('https://app.test.12build.com/login');
  
  // Wait for the form to be rendered
  await page.waitForSelector('[data-testid="login-username-input"]');
  
  await page.fill('[data-testid="login-username-input"]', 'intigriti-pentest+62a@12build.com');
  await page.fill('[data-testid="login-password-input"]', '518FE8195E85E84F');
  
  await page.click('[data-testid="submit-login-btn"]');
  
  // Wait for a few seconds to see where it redirects or what it calls
  await page.waitForTimeout(5000);

  const cookies = await context.cookies();
  console.log('COOKIES:', JSON.stringify(cookies, null, 2));

  await browser.close();
})();
