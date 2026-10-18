import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  b64uEncode, b64uDecode, newKeyBytes, importKey, deriveTopic, fingerprint,
  pairingUrl, parsePairing, seal, unseal, toFrames, Reassembler, ReplayGuard,
  KEY_BYTES, CHUNK_CHARS, MAX_CHUNKS,
} from '../../src/crypto.js';

const setup = async () => {
  const raw = newKeyBytes();
  return { raw, key: await importKey(raw), topic: await deriveTopic(raw) };
};

test('base64url round-trips all byte values and rejects junk', () => {
  const all = Uint8Array.from({ length: 256 }, (_, i) => i);
  assert.deepEqual(b64uDecode(b64uEncode(all)), all);
  assert.doesNotMatch(b64uEncode(all), /[+/=]/);
  assert.throws(() => b64uDecode('ab+c'));
  assert.throws(() => b64uDecode('a b'));
});

test('keys are 256-bit, random and non-extractable', async () => {
  const a = newKeyBytes(), b = newKeyBytes();
  assert.equal(a.length, KEY_BYTES);
  assert.notDeepEqual(a, b);
  const k = await importKey(a);
  assert.equal(k.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('raw', k));
  await assert.rejects(importKey(new Uint8Array(16)));
});

test('topic and fingerprint are deterministic, distinct and do not leak the key', async () => {
  const raw = newKeyBytes();
  const t1 = await deriveTopic(raw), t2 = await deriveTopic(raw);
  assert.equal(t1, t2);
  assert.match(t1, /^c[0-9a-f]{32}$/);
  assert.notEqual(t1, await deriveTopic(newKeyBytes()));
  assert.match(await fingerprint(raw), /^[0-9A-F]{4}-[0-9A-F]{4}$/);
  assert.ok(!t1.includes(Buffer.from(raw).toString('hex').slice(0, 8)));
});

test('pairing URL keeps the key in the fragment only and parses back', () => {
  const raw = newKeyBytes();
  const url = pairingUrl('https://me.github.io/clip/?x=1#old', raw);
  const u = new URL(url);
  assert.equal(u.search, '');
  assert.equal(u.pathname, '/clip/');
  assert.ok(u.hash.startsWith('#k='));
  assert.deepEqual(parsePairing(url), raw);
  assert.deepEqual(parsePairing('#k=' + b64uEncode(raw)), raw);
});

test('parsePairing rejects malformed input', () => {
  for (const bad of [null, '', 'hello', '#k=short', '#k=' + 'A'.repeat(44), 'https://x/?k=' + 'A'.repeat(43), 42]) {
    assert.equal(parsePairing(bad), null, String(bad));
  }
});

test('seal/unseal round-trip with unicode', async () => {
  const { key, topic } = await setup();
  const payload = { k: 'text', t: 'héllo 👋 \n\t<script>', ts: 1 };
  const { id, blob } = await seal(key, topic, payload);
  assert.deepEqual(await unseal(key, topic, id, blob), payload);
});

test('ciphertext reveals no plaintext and uses a fresh IV every time', async () => {
  const { key, topic } = await setup();
  const a = await seal(key, topic, { t: 'SECRET-MARKER' });
  const b = await seal(key, topic, { t: 'SECRET-MARKER' });
  assert.notEqual(a.blob, b.blob);
  assert.notEqual(a.blob.slice(0, 16), b.blob.slice(0, 16));
  assert.ok(!Buffer.from(b64uDecode(a.blob)).toString('latin1').includes('SECRET'));
});

test('wrong key, wrong topic, wrong id and tampering all fail authentication', async () => {
  const { key, topic } = await setup();
  const other = await setup();
  const { id, blob } = await seal(key, topic, { t: 'x' });
  await assert.rejects(unseal(other.key, topic, id, blob));
  await assert.rejects(unseal(key, other.topic, id, blob));
  await assert.rejects(unseal(key, topic, 'A'.repeat(16), blob));
  const bytes = b64uDecode(blob);
  for (const pos of [0, 12, bytes.length - 1]) {
    const t = bytes.slice();
    t[pos] ^= 1;
    await assert.rejects(unseal(key, topic, id, b64uEncode(t)), `flip at ${pos}`);
  }
  await assert.rejects(unseal(key, topic, id, b64uEncode(bytes.slice(0, 20))));
});

test('frames fit ntfy limits and reassemble in any order', async () => {
  const { key, topic } = await setup();
  const big = 'z'.repeat(20_000);
  const { id, blob } = await seal(key, topic, { t: big });
  const frames = toFrames(id, blob);
  assert.ok(frames.length > 1);
  for (const f of frames) assert.ok(new TextEncoder().encode(f).length < 4096);
  const rx = new Reassembler();
  const shuffled = frames.slice().reverse();
  let out = null;
  for (const f of shuffled) out = rx.push(f) || out;
  assert.equal(out.id, id);
  assert.equal((await unseal(key, topic, out.id, out.blob)).t, big);
});

test('single-frame messages pass straight through', () => {
  const rx = new Reassembler();
  assert.deepEqual(rx.push('AAAAAAAAAAAAAAAA.0.1.abc'), { id: 'AAAAAAAAAAAAAAAA', blob: 'abc' });
});

test('reassembler drops malformed, duplicate and inconsistent frames', () => {
  const rx = new Reassembler();
  const id = 'B'.repeat(16);
  for (const bad of ['', 'x', `${id}.1.1.a`, `${id}.0.0.a`, `${id}.0.99.a`, `${id}.0.2.a+b`, 'short.0.1.a', 42]) {
    assert.equal(rx.push(bad), null, String(bad));
  }
  assert.equal(rx.push(`${id}.0.2.aa`), null);
  assert.equal(rx.push(`${id}.0.2.XX`), null);        // duplicate index ignored
  assert.equal(rx.push(`${id}.1.3.bb`), null);        // count mismatch ignored
  assert.deepEqual(rx.push(`${id}.1.2.bb`), { id, blob: 'aabb' });
});

test('reassembler bounds memory and expires stale partials', () => {
  let t = 0;
  const rx = new Reassembler({ maxPending: 2, ttlMs: 1000, now: () => t });
  const ids = ['C', 'D', 'E'].map((c) => c.repeat(16));
  assert.equal(rx.push(`${ids[0]}.0.2.a`), null);
  assert.equal(rx.push(`${ids[1]}.0.2.a`), null);
  assert.equal(rx.push(`${ids[2]}.0.2.a`), null);
  assert.equal(rx.pending.size, 2);                    // third rejected
  t = 2000;
  assert.equal(rx.push(`${ids[2]}.0.2.a`), null);
  assert.equal(rx.pending.size, 1);                    // stale ones collected
});

test('toFrames refuses oversized payloads', () => {
  assert.throws(() => toFrames('F'.repeat(16), 'a'.repeat(CHUNK_CHARS * MAX_CHUNKS + 1)));
});

test('replay guard rejects repeats and out-of-window timestamps', () => {
  let t = 1_000_000;
  const g = new ReplayGuard({ windowMs: 1000, now: () => t });
  assert.equal(g.accept('a', t), true);
  assert.equal(g.accept('a', t), false);
  assert.equal(g.accept('b', t - 1001), false);
  assert.equal(g.accept('c', t + 1001), false);
  assert.equal(g.accept('d', 'now'), false);
  t += 5000;
  assert.equal(g.seen.has('a'), true);
  g.accept('e', t);
  assert.equal(g.seen.has('a'), false);                 // pruned
});
