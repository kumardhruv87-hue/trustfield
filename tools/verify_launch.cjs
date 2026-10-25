/* Browser acceptance checks. No real payment or provider calls. */
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

(async () => {
  const base = process.argv[2] || 'http://127.0.0.1:8766';
  const output = path.resolve('data/browser-qa');
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto(base + '/?utm_source=linkedin', { waitUntil: 'networkidle' });
  await page.screenshot({ path: path.join(output, 'desktop.png'), fullPage: true });
  if (!await page.getByRole('heading', { level: 1 }).innerText().then(t => t.includes('Know what to fix'))) throw Error('Wrong launch page');
  await page.locator('#target').fill('https://example.com');
  await page.locator('#scan-btn').click();
  await page.getByText('Please confirm you own this app or have permission to test it.').waitFor();
  const scan = { ok: true, id: 'browsercheck1', score: 65, grade: 'C', locked: true, total: 1,
    target: 'https://example.com', headline: 'Fix this before launch', verdict: 'Review the finding.',
    counts: { high: 1 }, checks_total: 33, report_url: '/r/browsercheck1',
    teaser: [{ title: 'Exposed key in public code', severity: 'high' }], top_actions: [] };
  let source;
  await page.route('**/api/scan', route => {
    source = route.request().postDataJSON().source;
    return route.fulfill({ json: scan });
  });
  await page.locator('#consent').check();
  await page.locator('#scan-btn').click();
  await page.locator('#scan-result:not(.hidden)').waitFor();
  if (!await page.locator('#scan-result').innerText().then(t => t.includes('Get fixes + PDF + re-check'))) throw Error('Missing useful paid offer');
  if (source !== 'linkedin') throw Error('Campaign source missing');
  scan.total = 0; scan.teaser = []; scan.headline = 'No issues found';
  await page.locator('#scan-btn').click();
  await page.getByText('No issues found in these checks. No fixes to buy.', { exact: false }).waitFor();
  if (await page.locator('#scan-result .unlock-btn').count()) throw Error('Empty scan still pushes checkout');
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto(base, { waitUntil: 'networkidle' });
  await page.screenshot({ path: path.join(output, 'mobile.png'), fullPage: true });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1);
  if (overflow) throw Error('Mobile horizontal overflow');
  await page.locator('[data-kind="repo"]').click();
  if (!await page.locator('#target-label').innerText().then(t => t.includes('GitHub'))) throw Error('Repo tab failed');
  if (errors.length) throw Error('Browser JS errors: ' + errors.join('; '));
  console.log(JSON.stringify({ desktop: 'pass', mobile: 'pass', form: 'pass', results: 'pass', source, browserErrors: errors, screenshots: output }));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
