import { test, expect, chromium } from '@playwright/test';
import { createBroker, instrument, readQr, qrToY4m, unlock, PHRASE } from './helpers.mjs';
import { parsePairing, deriveTopic, stretch, mixKey } from '../../src/crypto.js';

const BASE = 'http://localhost:4173/';

// Two isolated browser contexts = two devices that share nothing but the relay.
async function pair(browser, broker) {
  const ctxA = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
  const ctxB = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
  await broker.attach(ctxA);
  await broker.attach(ctxB);
  const a = await ctxA.newPage();
  const b = await ctxB.newPage();
  const pa = await instrument(a), pb = await instrument(b);
  await a.goto(BASE);
  await unlock(a);
  await expect(a.locator('#pair')).toBeVisible();
  const url = await readQr(a);
  await b.goto(url);
  await unlock(b);
  await expect(b.locator('#session')).toBeVisible();
  await expect(a.locator('#session')).toBeVisible();          // host leaves QR screen once paired
  await expect(a.locator('#status')).toHaveText('Paired');
  await expect(b.locator('#status')).toHaveText('Paired');
  return { a, b, url, problems: () => [...pa, ...pb], close: () => Promise.all([ctxA.close(), ctxB.close()]) };
}

async function sendText(page, text) {
  await page.fill('#text', text);
  await page.click('#send');
  await expect(page.locator('#text')).toHaveValue('');
}

test('QR encodes a same-origin URL with the key only in the fragment', async ({ browser }) => {
  const broker = createBroker();
  const s = await pair(browser, broker);
  const u = new URL(s.url);
  expect(u.origin).toBe('http://localhost:4173');
  expect(u.search).toBe('');
  expect(u.hash).toMatch(/^#k=[A-Za-z0-9_-]{43}$/);
  await s.close();
});

test('joiner strips the key from the address bar', async ({ browser }) => {
  const broker = createBroker();
  const s = await pair(browser, broker);
  expect(s.b.url()).toBe(BASE);
  expect(await s.b.evaluate(() => location.hash)).toBe('');
  await s.close();
});

test('both devices show the same fingerprint', async ({ browser }) => {
  const broker = createBroker();
  const s = await pair(browser, broker);
  const fa = await s.a.locator('#fp').textContent();
  expect(fa).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}$/);
  await expect(s.b.locator('#fp')).toHaveText(fa);
  await s.close();
});

test('text flows both ways', async ({ browser }) => {
  const broker = createBroker();
  const s = await pair(browser, broker);
  await sendText(s.a, 'from computer ✓');
  await expect(s.b.locator('#items li.in pre')).toHaveText(['from computer ✓']);
  await sendText(s.b, 'from phone\nline 2');
  await expect(s.a.locator('#items li.in pre')).toHaveText(['from phone\nline 2']);
  await expect(s.a.locator('#items li.out pre')).toHaveText(['from computer ✓']);
  expect(s.problems()).toEqual([]);
  await s.close();
});

test('relay only ever sees ciphertext: no plaintext, no key, uncached, no Firebase', async ({ browser }) => {
  const broker = createBroker();
  const s = await pair(browser, broker);
  const marker = 'TOP-SECRET-' + Math.random().toString(36).slice(2);
  await sendText(s.a, marker);
  await expect(s.b.locator('#items li.in pre')).toHaveText([marker]);
  const key = new URL(s.url).hash.slice(3);
  expect(broker.published.length).toBeGreaterThan(0);
  for (const p of broker.published) {
    expect(p.method).toBe('POST');
    expect(p.body).not.toContain(marker);
    expect(p.body).not.toContain(key);
    expect(p.body).not.toContain('text');            // message type is inside the ciphertext too
    expect(p.url).toContain('cache=no');
    expect(p.url).toContain('firebase=no');
    expect(p.url).not.toContain(key);
    expect(p.headers['cookie']).toBeUndefined();
    expect(p.headers['referer']).toBeUndefined();
    expect(p.body).toMatch(/^[A-Za-z0-9_-]{16}\.\d+\.\d+\.[A-Za-z0-9_-]+$/);
  }
  await s.close();
});

test('large text is chunked and arrives intact', async ({ browser }) => {
  const broker = createBroker();
  const s = await pair(browser, broker);
  const big = Array.from({ length: 3000 }, (_, i) => `line ${i} — ✓`).join('\n');
  await sendText(s.a, big);
  await expect(s.b.locator('#items li.in pre')).toHaveText([big], { timeout: 15000 });
  expect(broker.published.filter((p) => p.body.split('.')[2] !== '1').length).toBeGreaterThan(1);
  await s.close();
});

test('oversized text is refused locally and nothing is sent', async ({ browser }) => {
  const broker = createBroker();
  const s = await pair(browser, broker);
  const before = broker.published.length;
  await s.a.fill('#text', 'x'.repeat(65 * 1024));
  await s.a.click('#send');
  await expect(s.a.locator('#note')).toContainText('Too long');
  expect(broker.published.length).toBe(before);
  await s.close();
});

test('peer content is rendered as text, never as HTML', async ({ browser }) => {
  const broker = createBroker();
  const s = await pair(browser, broker);
  const evil = '<img src=x onerror="window.pwned=1"><b>bold</b>';
  await sendText(s.a, evil);
  await expect(s.b.locator('#items li.in pre')).toHaveText([evil]);
  expect(await s.b.locator('#items img, #items b').count()).toBe(0);
  expect(await s.b.evaluate(() => window.pwned)).toBeUndefined();
  await s.close();
});

test('injected, tampered and replayed frames are silently dropped', async ({ browser }) => {
  const broker = createBroker();
  const s = await pair(browser, broker);
  await sendText(s.a, 'legit');
  await expect(s.b.locator('#items li.in')).toHaveCount(1);
  const real = broker.published.at(-1);

  broker.inject(real.topic, real.body);                                   // replay
  broker.inject(real.topic, real.body.slice(0, -2) + (real.body.endsWith('A') ? 'BB' : 'AA')); // tamper
  broker.inject(real.topic, 'AAAAAAAAAAAAAAAA.0.1.' + 'Q'.repeat(60));    // forged, wrong key
  broker.inject(real.topic, 'not even a frame');
  broker.inject(real.topic, '{"k":"text","t":"plaintext injection"}');

  await s.b.waitForTimeout(500);
  await expect(s.b.locator('#items li.in')).toHaveCount(1);
  await expect(s.b.locator('#items li.in pre')).toHaveText(['legit']);
  expect(s.problems()).toEqual([]);
  await s.close();
});

test('a different session cannot read or reach this one', async ({ browser }) => {
  const broker = createBroker();
  const s1 = await pair(browser, broker);
  const s2 = await pair(browser, broker);
  expect(await s1.a.locator('#fp').textContent()).not.toBe(await s2.a.locator('#fp').textContent());
  await sendText(s1.a, 'only for session 1');
  await expect(s1.b.locator('#items li.in')).toHaveCount(1);
  await s2.b.waitForTimeout(300);
  await expect(s2.a.locator('#items li')).toHaveCount(0);
  await expect(s2.b.locator('#items li')).toHaveCount(0);
  await s1.close();
  await s2.close();
});

test('copy button puts the received text on the clipboard', async ({ browser }) => {
  const broker = createBroker();
  const s = await pair(browser, broker);
  await sendText(s.a, 'copy me 123');
  await s.b.locator('#items li.in .copy').click();
  await expect(s.b.locator('#items li.in .copy')).toHaveText('Copied');
  expect(await s.b.evaluate(() => navigator.clipboard.readText())).toBe('copy me 123');
  await s.close();
});

test('ending a session wipes the UI, notifies the peer and closes the socket', async ({ browser }) => {
  const broker = createBroker();
  const s = await pair(browser, broker);
  await sendText(s.a, 'temp');
  await expect(s.b.locator('#items li.in')).toHaveCount(1);
  const topic = broker.published.at(-1).topic;
  await s.b.click('#end');
  await expect(s.b.locator('#ended')).toBeVisible();
  await expect(s.b.locator('#items li')).toHaveCount(0);
  await expect(s.b.locator('#fp')).toHaveText('');
  await expect(s.a.locator('#status')).toHaveText('Other device left');
  await expect.poll(() => broker.subscribers(topic)).toBe(1);
  await s.close();
});

test('a fresh page load always generates a fresh key', async ({ browser }) => {
  const broker = createBroker();
  const ctx = await browser.newContext();
  await broker.attach(ctx);
  const p = await ctx.newPage();
  await p.goto(BASE);
  await unlock(p);
  const u1 = await readQr(p);
  await p.reload();
  await unlock(p);
  const u2 = await readQr(p);
  expect(u1).not.toBe(u2);
  await ctx.close();
});

test('CSP is present and blocks injected inline scripts', async ({ browser }) => {
  const ctx = await browser.newContext();
  await createBroker().attach(ctx);
  const p = await ctx.newPage();
  await p.goto(BASE);
  const csp = await p.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute('content');
  expect(csp).toContain("default-src 'none'");
  expect(csp).toContain('connect-src https://ntfy.sh wss://ntfy.sh');
  expect(csp).not.toContain('unsafe-inline');
  expect(csp).not.toContain('unsafe-eval');
  const ran = await p.evaluate(async () => {
    const s = document.createElement('script');
    s.textContent = 'window.__inj = 1';
    document.body.append(s);
    await new Promise((r) => setTimeout(r, 50));
    return window.__inj;
  });
  expect(ran).toBeUndefined();
  await ctx.close();
});

test('in-page camera scan pairs without the key ever touching the URL', async ({ browser }, info) => {
  const broker = createBroker();
  const ctxA = await browser.newContext();
  await broker.attach(ctxA);
  const a = await ctxA.newPage();
  await a.goto(BASE);
  await unlock(a);
  const url = await readQr(a);

  const video = info.outputPath('qr.y4m');
  await qrToY4m(url, video);
  const phone = await chromium.launch({
    args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream', `--use-file-for-fake-video-capture=${video}`],
  });
  const ctxB = await phone.newContext({ permissions: ['camera'] });
  await broker.attach(ctxB);
  const b = await ctxB.newPage();
  const problems = await instrument(b);
  await b.goto(BASE);
  await unlock(b, { phone: true });
  await b.click('#scan-btn');
  await expect(b.locator('#session')).toBeVisible({ timeout: 15000 });
  await expect(a.locator('#status')).toHaveText('Paired');
  await expect(b.locator('#fp')).toHaveText(await a.locator('#fp').textContent());
  expect(b.url()).toBe(BASE);

  await sendText(b, 'scanned path works');
  await expect(a.locator('#items li.in pre')).toHaveText(['scanned path works']);
  expect(problems).toEqual([]);
  await phone.close();
  await ctxA.close();
});

// ---------- gate ----------
test('locked page is a bare 404: no app UI, no key, no network', async ({ browser }) => {
  const broker = createBroker();
  const ctx = await browser.newContext();
  await broker.attach(ctx);
  const p = await ctx.newPage();
  const ntfy = [];
  p.on('request', (r) => { if (r.url().includes('ntfy.sh')) ntfy.push(r.url()); });
  p.on('websocket', (w) => ntfy.push(w.url()));
  await p.goto(BASE);
  await expect(p).toHaveTitle('404 Not Found');
  await expect(p.locator('#g404')).toHaveText('404');
  for (const id of ['#top', '#app', '#foot', '#gate-form']) await expect(p.locator(id)).toBeHidden();
  const qrBlank = await p.evaluate(() => {
    const c = document.getElementById('qr');
    return c.getContext('2d').getImageData(0, 0, c.width, c.height).data.every((v) => v === 0);
  });
  expect(qrBlank).toBe(true);
  await p.waitForTimeout(500);
  expect(ntfy).toEqual([]);
  await ctx.close();
});

test('wrong phrase keeps the decoy, silently', async ({ browser }) => {
  const ctx = await browser.newContext();
  await createBroker().attach(ctx);
  const p = await ctx.newPage();
  await p.goto(BASE);
  await p.keyboard.type('open sesame');
  await p.keyboard.press('Enter');
  await p.waitForTimeout(1500);
  await expect(p.locator('#g404')).toBeVisible();
  await expect(p.locator('#app')).toBeHidden();
  await unlock(p); // buffer was reset: the right phrase still works afterwards
  await expect(p.locator('#pair')).toBeVisible();
  await expect(p).toHaveTitle('Clip');
  await ctx.close();
});

test('phrase is forgiving about case and spacing', async ({ browser }) => {
  const ctx = await browser.newContext();
  await createBroker().attach(ctx);
  const p = await ctx.newPage();
  await p.goto(BASE);
  await unlock(p, { phrase: '  ' + PHRASE.toUpperCase().replace(/ /g, '   ') + ' ' });
  await expect(p.locator('#pair')).toBeVisible();
  await ctx.close();
});

test('pairing fragment is stripped before the gate is even passed', async ({ browser }) => {
  const s = await pair(browser, createBroker());
  const ctx = await browser.newContext();
  await createBroker().attach(ctx);
  const c = await ctx.newPage();
  await c.goto(s.url);
  await expect(c.locator('#g404')).toBeVisible();
  expect(c.url()).toBe(BASE);
  await ctx.close();
  await s.close();
});

test('the QR alone is not enough: traffic uses a key that also needs the phrase', async ({ browser }) => {
  const broker = createBroker();
  const s = await pair(browser, broker);
  await sendText(s.a, 'needs both factors');
  await expect(s.b.locator('#items li.in')).toHaveCount(1);
  const qrRaw = parsePairing(s.url);
  const qrOnlyTopic = await deriveTopic(qrRaw);
  const mixedTopic = await deriveTopic(await mixKey(qrRaw, (await stretch(PHRASE)).pepper));
  const seen = new Set(broker.published.map((p) => p.topic));
  expect(seen.has(qrOnlyTopic)).toBe(false);
  expect([...seen]).toEqual([mixedTopic]);
  await s.close();
});

test('triple-tap shows a real, password-manager friendly field', async ({ browser }) => {
  const ctx = await browser.newContext({ hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } });
  await createBroker().attach(ctx);
  const p = await ctx.newPage();
  const problems = await instrument(p);
  await p.goto(BASE);
  await expect(p.locator('#gate-in')).toBeHidden();
  await p.click('#g404', { clickCount: 3 });
  const field = p.locator('#gate-in');
  await expect(field).toBeVisible();
  await expect(field).toBeFocused();
  // What password managers look for: a form, a username, a current-password field.
  await expect(p.locator('form#gate-form')).toHaveCount(1);
  await expect(field).toHaveAttribute('type', 'password');
  await expect(field).toHaveAttribute('autocomplete', 'current-password');
  await expect(field).toHaveAttribute('name', 'password');
  await expect(p.locator('#gate-user')).toHaveAttribute('autocomplete', 'username');
  const box = await field.boundingBox();
  expect(box.width).toBeGreaterThan(150);

  await p.keyboard.type('lapin');
  await p.click('#gate-eye');
  await expect(field).toHaveAttribute('type', 'text');
  await expect(field).toHaveValue('lapin');
  await expect(field).toBeFocused();
  await p.click('#gate-eye');
  await expect(field).toHaveAttribute('type', 'password');

  await p.keyboard.type(' test phrase');
  await p.click('#gate-go');
  await expect(p.locator('#pair')).toBeVisible();
  await expect(p.locator('#gate')).toHaveCount(0);
  expect(problems).toEqual([]);              // incl. no CSP form-action violation on submit
  await ctx.close();
});

test('wrong phrase in the field clears it and stays locked', async ({ browser }) => {
  const ctx = await browser.newContext();
  await createBroker().attach(ctx);
  const p = await ctx.newPage();
  await p.goto(BASE);
  await p.click('#g404', { clickCount: 3 });
  await p.keyboard.type('nope nope');
  await p.keyboard.press('Enter');
  await expect(p.locator('#gate-in')).toHaveValue('');
  await expect(p.locator('#app')).toBeHidden();
  await p.keyboard.type(PHRASE);
  await p.keyboard.press('Enter');
  await expect(p.locator('#pair')).toBeVisible();
  await ctx.close();
});

test('dismissing an empty field brings back the plain decoy', async ({ browser }) => {
  const ctx = await browser.newContext();
  await createBroker().attach(ctx);
  const p = await ctx.newPage();
  await p.goto(BASE);
  await p.click('#g404', { clickCount: 3 });
  await expect(p.locator('#gate-in')).toBeVisible();
  await p.click('body', { position: { x: 5, y: 5 } });
  await expect(p.locator('#gate-form')).toBeHidden();
  await ctx.close();
});
