import qrcode from 'qrcode-generator';
import jsQR from 'jsqr';
import {
  newKeyBytes, importKey, deriveTopic, fingerprint, pairingUrl, parsePairing,
  seal, unseal, toFrames, Reassembler, ReplayGuard, textBytes, MAX_TEXT_BYTES, b64uEncode,
  gateCheck, mixKey,
} from './crypto.js';
import { Relay } from './relay.js';

const IDLE_MS = 15 * 60 * 1000;
const $ = (id) => document.getElementById(id);
const views = ['pair', 'scan', 'session', 'ended'];

let s = null;          // current session
let idleTimer = null;
let scanStop = null;
let pepper = null;      // set once the gate is passed; required to derive any session key

const GATE = __GATE__;

function show(view) {
  for (const v of views) $(v).hidden = v !== view;
}

function setStatus(text, kind) {
  const el = $('status');
  el.textContent = text;
  el.dataset.kind = kind;
}

function note(text) {
  const el = $('note');
  el.textContent = text;
  el.hidden = !text;
}

function bumpIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => end('Session ended after 15 min of inactivity.'), IDLE_MS);
}

// ---------- session ----------
async function startSession(raw, role) {
  stopSession();
  const key = await importKey(raw);
  const topic = await deriveTopic(raw);
  const fp = await fingerprint(raw);
  s = {
    role, key, topic, fp,
    me: b64uEncode(crypto.getRandomValues(new Uint8Array(9))),
    peers: new Set(),
    rx: new Reassembler(),
    guard: new ReplayGuard(),
    relay: null,
  };
  raw.fill(0); // the CryptoKey is non-extractable; drop the raw copy
  $('fp').textContent = fp;
  const cur = s;
  s.relay = new Relay(topic, {
    onFrame: (f) => onFrame(cur, f),
    onStatus: (st) => {
      if (cur !== s) return;
      if (st === 'online') {
        setStatus(cur.peers.size ? 'Paired' : 'Waiting for other device', cur.peers.size ? 'ok' : 'wait');
        send({ k: 'hello', r: 0 }).catch(() => {});
      } else setStatus(st === 'connecting' ? 'Connecting…' : 'Relay offline, retrying…', 'bad');
    },
  });
  s.relay.connect();
  bumpIdle();
  return { raw, fp };
}

function stopSession() {
  if (!s) return;
  s.relay.close();
  s = null;
}

async function send(body) {
  const cur = s;
  if (!cur) throw new Error('no session');
  const { id, blob } = await seal(cur.key, cur.topic, { ...body, s: cur.me, ts: Date.now() });
  cur.guard.accept(id, Date.now()); // never process our own echo
  for (const f of toFrames(id, blob)) await cur.relay.publish(f);
}

async function onFrame(cur, frame) {
  if (cur !== s) return;
  const done = cur.rx.push(frame);
  if (!done) return;
  let msg;
  try {
    msg = await unseal(cur.key, cur.topic, done.id, done.blob);
  } catch {
    return; // not ours, tampered, or garbage: drop silently
  }
  if (!msg || msg.s === cur.me || !cur.guard.accept(done.id, msg.ts)) return;

  if (msg.k === 'hello') {
    const isNew = !cur.peers.has(msg.s);
    cur.peers.add(msg.s);
    setStatus('Paired', 'ok');
    if (cur.role === 'host') {
      $('back').hidden = false;
      if (isNew) show('session');
    }
    if (msg.r === 0) send({ k: 'hello', r: 1 }).catch(() => {});
    if (isNew) bumpIdle();
  } else if (msg.k === 'text' && typeof msg.t === 'string') {
    addItem(msg.t, 'in');
    bumpIdle();
  } else if (msg.k === 'bye') {
    cur.peers.delete(msg.s);
    if (!cur.peers.size) setStatus('Other device left', 'wait');
  }
}

function end(reason) {
  if (s) send({ k: 'bye' }).catch(() => {});
  setTimeout(stopSession, 300);
  clearTimeout(idleTimer);
  stopScan();
  $('items').replaceChildren();
  $('text').value = '';
  $('qr').getContext('2d').clearRect(0, 0, $('qr').width, $('qr').height);
  $('ended-reason').textContent = reason;
  setStatus('Ended', 'bad');
  $('fp').textContent = '';
  show('ended');
}

// ---------- UI: items ----------
function addItem(text, dir) {
  const li = document.createElement('li');
  li.className = dir;
  const pre = document.createElement('pre');
  pre.textContent = text; // never innerHTML: peer content is untrusted
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = 'Copy';
  btn.className = 'copy';
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = 'Copied';
    } catch {
      const r = document.createRange();
      r.selectNodeContents(pre);
      getSelection().removeAllRanges();
      getSelection().addRange(r);
      btn.textContent = 'Selected';
    }
    setTimeout(() => (btn.textContent = 'Copy'), 1500);
  });
  const meta = document.createElement('span');
  meta.className = 'meta';
  meta.textContent = (dir === 'in' ? 'Received ' : 'Sent ') + new Date().toLocaleTimeString();
  li.append(meta, pre, btn);
  $('items').prepend(li);
}

async function onSend() {
  const t = $('text').value;
  if (!t) return;
  if (textBytes(t) > MAX_TEXT_BYTES) return note(`Too long: max ${MAX_TEXT_BYTES / 1024} KB.`);
  $('send').disabled = true;
  try {
    await send({ k: 'text', t });
    addItem(t, 'out');
    $('text').value = '';
    note('');
    bumpIdle();
  } catch (e) {
    note('Send failed: ' + e.message);
  } finally {
    $('send').disabled = false;
  }
}

// ---------- QR ----------
function drawQr(text) {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  const n = qr.getModuleCount();
  const quiet = 4;
  const cell = Math.max(4, Math.floor(320 / (n + quiet * 2)));
  const size = cell * (n + quiet * 2);
  const c = $('qr');
  c.width = c.height = size;
  const g = c.getContext('2d');
  g.fillStyle = '#fff';
  g.fillRect(0, 0, size, size);
  g.fillStyle = '#000';
  for (let r = 0; r < n; r++)
    for (let col = 0; col < n; col++)
      if (qr.isDark(r, col)) g.fillRect((col + quiet) * cell, (r + quiet) * cell, cell, cell);
}

async function host() {
  const qrRaw = newKeyBytes();
  drawQr(pairingUrl(location.origin + location.pathname, qrRaw));
  const raw = await mixKey(qrRaw, pepper);
  qrRaw.fill(0);
  await startSession(raw, 'host');
  $('show-qr').hidden = false;
  $('back').hidden = true;
  show('pair');
}

async function join(qrRaw) {
  stopScan();
  const raw = await mixKey(qrRaw, pepper);
  qrRaw.fill(0);
  await startSession(raw, 'join');
  $('show-qr').hidden = true;
  setStatus('Connecting…', 'wait');
  show('session');
}

// ---------- scanner ----------
async function startScan() {
  note('');
  stopSession();
  show('scan');
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
  } catch (e) {
    $('scan-err').textContent = 'Camera unavailable: ' + e.message;
    return;
  }
  const video = $('video');
  video.srcObject = stream;
  await video.play().catch(() => {});
  const canvas = document.createElement('canvas');
  const g = canvas.getContext('2d', { willReadFrequently: true });
  const detector = 'BarcodeDetector' in window ? new window.BarcodeDetector({ formats: ['qr_code'] }) : null;
  let alive = true;
  scanStop = () => {
    alive = false;
    stream.getTracks().forEach((t) => t.stop());
    video.srcObject = null;
    scanStop = null;
  };
  const tick = async () => {
    if (!alive) return;
    if (video.readyState >= 2 && video.videoWidth) {
      let text = null;
      if (detector) {
        try { text = (await detector.detect(video))[0]?.rawValue ?? null; } catch { /* fall through */ }
      }
      if (!text) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        g.drawImage(video, 0, 0);
        const img = g.getImageData(0, 0, canvas.width, canvas.height);
        text = jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' })?.data ?? null;
      }
      const raw = text && parsePairing(text);
      if (raw) return join(raw);
      if (text) $('scan-err').textContent = 'Not a Clip pairing code.';
    }
    setTimeout(tick, 120);
  };
  tick();
}

function stopScan() {
  if (scanStop) scanStop();
}

// ---------- gate ----------
// Decoy "404" until the phrase is entered. Nothing is generated or sent before that.
function gate(onOpen) {
  const input = $('gate-in');
  let buf = '';
  let busy = false;
  let taps = 0, tapT = 0;

  const attempt = async (phrase) => {
    if (busy || !phrase) return;
    busy = true;
    const p = await gateCheck(phrase, GATE).catch(() => null);
    busy = false;
    buf = '';
    input.value = '';
    if (!p) return; // wrong: stay a boring 404, no feedback
    pepper = p;
    document.removeEventListener('keydown', onKey);
    input.blur();
    $('gate').remove();
    for (const id of ['top', 'app', 'foot']) $(id).hidden = false;
    document.title = 'Clip';
    onOpen();
  };

  // Desktop: type anywhere, Enter.
  const onKey = (e) => {
    if (e.target === input || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === 'Enter') attempt(buf);
    else if (e.key === 'Backspace') buf = buf.slice(0, -1);
    else if (e.key === 'Escape') buf = '';
    else if (e.key.length === 1 && buf.length < 256) buf += e.key;
  };
  document.addEventListener('keydown', onKey);

  // Phone: triple-tap the 404 to summon the keyboard, type, Enter.
  $('g404').addEventListener('click', () => {
    const t = Date.now();
    taps = t - tapT < 600 ? taps + 1 : 1;
    tapT = t;
    if (taps >= 3) { taps = 0; input.focus(); }
  });
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); attempt(input.value); } });
}

// ---------- boot ----------
function boot() {
  $('send').addEventListener('click', onSend);
  $('text').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) onSend();
  });
  $('paste').addEventListener('click', async () => {
    try { $('text').value = await navigator.clipboard.readText(); } catch { note('Clipboard read blocked: paste manually.'); }
  });
  $('scan-btn').addEventListener('click', startScan);
  $('scan-cancel').addEventListener('click', () => { stopScan(); host(); });
  $('show-qr').addEventListener('click', () => { if (s && s.role === 'host') show('pair'); });
  $('back').addEventListener('click', () => show('session'));
  $('end').addEventListener('click', () => end('Session ended. Keys wiped.'));
  $('restart').addEventListener('click', () => host());
  window.addEventListener('pagehide', () => { if (s) end('Session ended.'); });

  const raw = parsePairing(location.hash);
  // Strip the key from the address bar / current history entry immediately, before the gate.
  if (location.hash) history.replaceState(null, '', location.pathname);
  gate(() => (raw ? join(raw) : host()));
}

boot();
