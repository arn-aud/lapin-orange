// Pure, isomorphic crypto + framing. Runs in browsers and Node >= 20 (globalThis.crypto).
// Nothing here touches the network or the DOM, so it is fully unit-testable.

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();

export const KEY_BYTES = 32;            // AES-256
export const IV_BYTES = 12;             // GCM standard nonce
export const ID_BYTES = 12;             // per-message random id
export const MAX_TEXT_BYTES = 64 * 1024;
export const CHUNK_CHARS = 3500;        // ntfy turns bodies > 4096 B into attachments
export const MAX_CHUNKS = 32;
export const REPLAY_WINDOW_MS = 10 * 60 * 1000;

// ---------- encoding ----------
export function b64uEncode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64uDecode(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) throw new Error('bad base64url');
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

async function sha256(label, raw) {
  const l = te.encode(label);
  const buf = new Uint8Array(l.length + raw.length);
  buf.set(l, 0);
  buf.set(raw, l.length);
  return new Uint8Array(await subtle.digest('SHA-256', buf));
}

// ---------- keys ----------
export function newKeyBytes() {
  return globalThis.crypto.getRandomValues(new Uint8Array(KEY_BYTES));
}

export async function importKey(raw) {
  if (!(raw instanceof Uint8Array) || raw.length !== KEY_BYTES) throw new Error('bad key length');
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// Relay topic is derived from the key with domain separation, so the QR carries only the key.
// 128 bits of topic entropy: unguessable, and reveals nothing about the key.
export async function deriveTopic(raw) {
  return 'c' + hex((await sha256('clip/topic/v1', raw)).slice(0, 16));
}

// Short code shown on both screens so you can eyeball that both ends hold the same key.
export async function fingerprint(raw) {
  const h = hex((await sha256('clip/fp/v1', raw)).slice(0, 4)).toUpperCase();
  return h.slice(0, 4) + '-' + h.slice(4);
}

// ---------- pairing payload ----------
// QR content is a full URL (so a native camera app also works), but the key lives only
// in the #fragment, which browsers never send to the server.
export function pairingUrl(base, raw) {
  const u = new URL(base);
  u.hash = 'k=' + b64uEncode(raw);
  u.search = '';
  return u.toString();
}

export function parsePairing(text) {
  if (typeof text !== 'string') return null;
  const m = text.match(/(?:^|[#&])k=([A-Za-z0-9_-]{43})(?:$|&)/);
  if (!m) return null;
  try {
    const raw = b64uDecode(m[1]);
    return raw.length === KEY_BYTES ? raw : null;
  } catch {
    return null;
  }
}

// ---------- sealing ----------
const aad = (topic, id) => te.encode(`clip/v1|${topic}|${id}`);

export async function seal(key, topic, payload) {
  const id = b64uEncode(globalThis.crypto.getRandomValues(new Uint8Array(ID_BYTES)));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const pt = te.encode(JSON.stringify(payload));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(topic, id) }, key, pt));
  const blob = new Uint8Array(iv.length + ct.length);
  blob.set(iv, 0);
  blob.set(ct, iv.length);
  return { id, blob: b64uEncode(blob) };
}

export async function unseal(key, topic, id, blob) {
  const bytes = b64uDecode(blob);
  if (bytes.length < IV_BYTES + 16) throw new Error('short ciphertext');
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.slice(0, IV_BYTES), additionalData: aad(topic, id) },
    key,
    bytes.slice(IV_BYTES),
  );
  return JSON.parse(td.decode(pt));
}

// ---------- framing ----------
// Wire format per relay message: "<id>.<index>.<count>.<part>"
export function toFrames(id, blob, size = CHUNK_CHARS) {
  const n = Math.max(1, Math.ceil(blob.length / size));
  if (n > MAX_CHUNKS) throw new Error('message too large');
  const frames = [];
  for (let i = 0; i < n; i++) frames.push(`${id}.${i}.${n}.${blob.slice(i * size, (i + 1) * size)}`);
  return frames;
}

const FRAME_RE = /^([A-Za-z0-9_-]{16})\.(\d{1,2})\.(\d{1,2})\.([A-Za-z0-9_-]*)$/;

export class Reassembler {
  constructor({ maxPending = 16, ttlMs = 60_000, now = () => Date.now() } = {}) {
    this.pending = new Map();
    this.maxPending = maxPending;
    this.ttlMs = ttlMs;
    this.now = now;
  }

  // Returns {id, blob} once complete, otherwise null. Malformed frames are dropped silently.
  push(frame) {
    const m = typeof frame === 'string' && frame.match(FRAME_RE);
    if (!m) return null;
    const [, id, is, ns, part] = m;
    const i = Number(is), n = Number(ns);
    if (n < 1 || n > MAX_CHUNKS || i >= n) return null;
    if (n === 1) return { id, blob: part };

    this.#gc();
    let e = this.pending.get(id);
    if (!e) {
      if (this.pending.size >= this.maxPending) return null;
      e = { n, parts: new Array(n), got: 0, t: this.now() };
      this.pending.set(id, e);
    }
    if (e.n !== n || e.parts[i] !== undefined) return null;
    e.parts[i] = part;
    if (++e.got < n) return null;
    this.pending.delete(id);
    return { id, blob: e.parts.join('') };
  }

  #gc() {
    const t = this.now();
    for (const [id, e] of this.pending) if (t - e.t > this.ttlMs) this.pending.delete(id);
  }
}

// ---------- replay protection ----------
export class ReplayGuard {
  constructor({ windowMs = REPLAY_WINDOW_MS, now = () => Date.now() } = {}) {
    this.seen = new Map();
    this.windowMs = windowMs;
    this.now = now;
  }

  accept(id, ts) {
    const t = this.now();
    for (const [k, v] of this.seen) if (t - v > this.windowMs) this.seen.delete(k);
    if (typeof ts !== 'number' || Math.abs(t - ts) > this.windowMs) return false;
    if (this.seen.has(id)) return false;
    this.seen.set(id, t);
    return true;
  }
}

export function textBytes(s) {
  return te.encode(s).length;
}

// ---------- gate (passphrase) ----------
// Discretion gate. The phrase is also mixed into the session key, so a QR photo alone is useless.
export const GATE_SALT = 'clip/gate/v1';
export const GATE_ITER = 600_000;

// Forgiving on phone keyboards: case, extra spaces, auto-capitalisation, unicode forms.
export function normalizePhrase(p) {
  return String(p).normalize('NFKC').trim().toLowerCase().replace(/\s+/g, ' ');
}

// 512 bits from PBKDF2: first half = public verifier, second half = secret pepper.
// Halves of a PRF output are independent, so the verifier reveals nothing about the pepper.
export async function stretch(phrase, { salt = GATE_SALT, iter = GATE_ITER } = {}) {
  const base = await subtle.importKey('raw', te.encode(normalizePhrase(phrase)), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: te.encode(salt), iterations: iter }, base, 512));
  return { verifier: b64uEncode(bits.slice(0, 32)), pepper: bits.slice(32) };
}

// Returns the pepper when the phrase is right, null otherwise.
export async function gateCheck(phrase, gate) {
  const { verifier, pepper } = await stretch(phrase, gate);
  return verifier === gate.v ? pepper : null;
}

// Session key = HKDF(QR key, salt = pepper). Both are needed to derive topic and AES key.
export async function mixKey(qrRaw, pepper) {
  const ikm = await subtle.importKey('raw', qrRaw, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: pepper, info: te.encode('clip/key/v1') }, ikm, 256));
}
