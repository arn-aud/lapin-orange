# Clip

Ephemeral, end-to-end encrypted text transfer between two devices. One static HTML file, paired by QR code. No accounts, no storage.

## Use

0. The page opens as a plain **404**. Unlock it: on a computer type the passphrase anywhere and press Enter; on a phone triple-tap “404”, type it, press Enter. Wrong phrase: nothing happens.
1. Open `https://arn-aud.github.io/lapin-orange/` on the computer. It shows a QR code.
2. Open the same address on the phone, tap **Scan a code**, point at the screen.
3. Check the code in the top bar (e.g. `3F9A-C210`) matches on both screens.
4. Paste, **Send** (or Ctrl/⌘+Enter). Tap **Copy** on the other side.
5. **End** when done. Sessions also end after 15 min idle or when a tab closes.

Scanning with the phone's native camera app also works, but prefer the in-page scanner (see threat model).

## How it works

- **Gate**: the passphrase (repo secret `GATE_PASSPHRASE`, never committed) is stretched with PBKDF2-SHA256, 600k iterations, into 512 bits. The first half is embedded as a public verifier; the second half is a secret pepper. Session key = `HKDF(QR key, salt = pepper)`, so a photo of the QR is useless without the phrase. Before unlock the page generates no key and opens no connection. It is a discretion layer: the verifier is public, so a weak phrase can be brute-forced offline. Use 4+ random words.

- The computer generates a random 256-bit key in the browser. The QR carries it in the URL `#fragment`, which browsers never send to any server.
- Relay topic = `SHA-256("clip/topic/v1" ‖ key)` truncated to 128 bits. The QR holds only the key.
- Each message: AES-256-GCM, random 96-bit IV, AAD binds it to the topic and a random message id. Tampering, wrong key, or cross-session frames fail authentication and are dropped.
- Replay protection: message ids are remembered; timestamps outside ±10 min are rejected.
- Relay: [ntfy.sh](https://ntfy.sh) over WebSocket, published with `cache=no&firebase=no` (forwarded live, not stored, not pushed to Google). It sees only opaque frames on a random topic.
- Large text is split into <4 KB frames (ntfy limit), max 64 KB of text.
- Strict CSP: `default-src 'none'`, script/style allowed by SHA-256 hash only, network allowed only to the relay. No third-party scripts, no CDN, no analytics.
- Peer text is rendered with `textContent` only (never HTML).

## Threat model — be precise about what this does and does not protect

**Protected against**
- The relay operator, your network, corporate TLS inspection: they see ciphertext, a random topic, sizes and timing. Nothing else.
- Injection/forgery/replay by anyone who knows or guesses the topic.

**Not protected against**
- **A compromised or monitored endpoint.** If your work computer runs EDR/DLP, screen or clipboard monitoring, it sees the plaintext and the QR (i.e. the key). No web page can defeat that. Assume a managed work laptop is monitored.
- **A malicious build of the page.** You trust whatever JS GitHub Pages serves. Mitigations: the build is unminified and deterministic, and `GATE_PASSPHRASE='…' npm run verify -- <url>` checks the deployed file is byte-identical to your local build. Enable 2FA on GitHub; a hijacked account means a hijacked page.
- **Shoulder surfing / a photo of the QR** while it's displayed. It hides once paired; end the session if in doubt.
- **Native camera pairing**: the phone browser records the URL (with key) in history before the page strips it. If history syncs to a cloud account, that account + someone who also recorded ciphertext at the relay could decrypt that session. The in-page scanner avoids this entirely: the key never enters a URL on the phone.
- **Metadata**: the relay sees your IPs, when you talk, and message sizes.
- **Availability**: ntfy.sh applies per-IP rate limits to anonymous use; behind a shared corporate IP the quota is shared. Corporate proxies may block ntfy.sh outright. `cache=no` means a device that's briefly disconnected misses messages sent meanwhile.

**Policy, not crypto**: moving data off a work machine may breach your employer's rules regardless of encryption. Check before using it for work data.

## Develop

```sh
npm ci
npx playwright install chromium
npm test            # 19 unit + 20 end-to-end tests (test phrase: 'lapin test phrase')
GATE_PASSPHRASE='…' npm run build   # -> dist/index.html
RELAY_URL=https://ntfy.example.com npm run build   # self-hosted ntfy (CSP follows)
```

The E2E suite runs two isolated browsers (two "devices") against an in-process fake relay that records every byte it receives, and asserts it never sees plaintext or the key. It also covers chunking, tampering, replay, cross-session isolation, XSS, CSP enforcement, clipboard, session teardown, and real camera scanning (Chromium fake camera fed a QR video).

## Deploy

Push to `main`. Requires repo secret `GATE_PASSPHRASE` (Settings → Secrets and variables → Actions). The workflow runs all tests, builds, and deploys `dist/` to GitHub Pages only if everything passes. One-time setup: repo **Settings → Pages → Source: GitHub Actions**.

## Files

| Path | Purpose |
|---|---|
| `src/crypto.js` | Keys, AES-GCM sealing, framing, replay guard (pure, unit-tested) |
| `src/relay.js` | ntfy WebSocket/POST transport |
| `src/app.js` | UI, pairing, QR render and scan |
| `build.mjs` | Bundles to one HTML file, computes CSP hashes |
| `scripts/verify-live.mjs` | Checks the deployed page matches the source build |
