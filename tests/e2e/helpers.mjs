import jsQR from 'jsqr';
import qrcode from 'qrcode-generator';
import { writeFile } from 'node:fs/promises';

export const PHRASE = 'lapin test phrase'; // matches playwright.config.mjs build env

// In-process stand-in for ntfy.sh. Records every byte the "server" receives,
// so tests can assert the relay never sees plaintext or the key.
export function createBroker() {
  const subs = new Map(); // topic -> Set<WebSocketRoute>
  const published = [];   // { topic, url, body }

  const broadcast = (topic, message) => {
    for (const ws of subs.get(topic) || []) ws.send(JSON.stringify({ event: 'message', topic, message }));
  };

  return {
    published,
    subscribers: (topic) => (subs.get(topic) || new Set()).size,
    inject: broadcast,
    async attach(context) {
      await context.routeWebSocket(/^wss:\/\/ntfy\.sh\/[^/]+\/ws$/, (ws) => {
        const topic = new URL(ws.url()).pathname.split('/')[1];
        if (!subs.has(topic)) subs.set(topic, new Set());
        subs.get(topic).add(ws);
        ws.onClose(() => subs.get(topic).delete(ws));
        ws.send(JSON.stringify({ event: 'open', topic }));
      });
      await context.route(/^https:\/\/ntfy\.sh\//, async (route) => {
        const req = route.request();
        const url = new URL(req.url());
        const topic = url.pathname.split('/')[1];
        const body = req.postData() ?? '';
        published.push({ topic, url: req.url(), body, method: req.method(), headers: req.headers() });
        broadcast(topic, body);
        await route.fulfill({
          status: 200,
          headers: { 'access-control-allow-origin': '*' },
          contentType: 'application/json',
          body: '{}',
        });
      });
    },
  };
}

// Watch for CSP violations, page errors and any request leaving localhost/ntfy.sh.
export async function instrument(page) {
  const problems = [];
  page.on('pageerror', (e) => problems.push('pageerror: ' + e.message));
  page.on('console', (m) => { if (m.type() === 'error') problems.push('console: ' + m.text()); });
  page.on('request', (r) => {
    const u = new URL(r.url());
    if (!['localhost', '127.0.0.1', 'ntfy.sh'].includes(u.hostname)) problems.push('unexpected request: ' + r.url());
  });
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) =>
      console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI}`));
  });
  return problems;
}

// Decode the QR the host page is displaying, from its actual pixels.
export async function readQr(page) {
  const img = await page.evaluate(() => {
    const c = document.getElementById('qr');
    const d = c.getContext('2d').getImageData(0, 0, c.width, c.height);
    return { w: d.width, h: d.height, data: Array.from(d.data) };
  });
  const r = jsQR(Uint8ClampedArray.from(img.data), img.w, img.h);
  if (!r) throw new Error('QR not decodable');
  return r.data;
}

// Render a QR into a .y4m video so Chromium's fake camera "sees" it.
export async function qrToY4m(text, path, { w = 640, h = 480, frames = 3 } = {}) {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  const n = qr.getModuleCount();
  const cell = Math.floor(Math.min(w, h) * 0.85 / (n + 8));
  const size = cell * (n + 8);
  const ox = Math.floor((w - size) / 2), oy = Math.floor((h - size) / 2);
  const Y = Buffer.alloc(w * h, 235);
  for (let y = 0; y < h; y++)
    for (let x = 0; x < w; x++) {
      const mx = Math.floor((x - ox) / cell) - 4, my = Math.floor((y - oy) / cell) - 4;
      if (mx >= 0 && my >= 0 && mx < n && my < n && qr.isDark(my, mx)) Y[y * w + x] = 16;
    }
  const UV = Buffer.alloc((w / 2) * (h / 2) * 2, 128);
  const header = Buffer.from(`YUV4MPEG2 W${w} H${h} F15:1 Ip A1:1 C420jpeg\n`);
  const frame = Buffer.concat([Buffer.from('FRAME\n'), Y, UV]);
  await writeFile(path, Buffer.concat([header, ...Array(frames).fill(frame)]));
}

// Pass the decoy gate like a user would: type anywhere (desktop) or triple-tap the 404 (phone).
export async function unlock(page, { phrase = PHRASE, phone = false } = {}) {
  await page.locator('#g404').waitFor();
  if (phone) {
    await page.click('#g404', { clickCount: 3 });
    await page.locator('#gate-in').waitFor({ state: 'visible' });
    await page.waitForFunction(() => document.activeElement?.id === 'gate-in');
  }
  await page.keyboard.type(phrase);
  await page.keyboard.press('Enter');
  if (phrase.trim().toLowerCase().replace(/\s+/g, ' ') === PHRASE) {
    await page.locator('#app').waitFor({ state: 'visible', timeout: 15000 });
  }
}
