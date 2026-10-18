// Builds dist/index.html: one self-contained file, inline script + style locked by CSP hashes.
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { stretch, GATE_SALT, GATE_ITER } from './src/crypto.js';

// Fail closed: no phrase, no build. The phrase itself never lands in the output, only its verifier.
const phrase = process.env.GATE_PASSPHRASE;
if (!phrase || !phrase.trim()) throw new Error('GATE_PASSPHRASE env var required');
const gate = { salt: GATE_SALT, iter: GATE_ITER, v: (await stretch(phrase)).verifier };

const relay = new URL(process.env.RELAY_URL || 'https://ntfy.sh');
if (relay.protocol !== 'https:' || relay.pathname !== '/') throw new Error('RELAY_URL must be https://host with no path');
const relayHttp = relay.origin, relayWs = relay.origin.replace(/^https/, 'wss');

const sha = (s) => `'sha256-${createHash('sha256').update(s, 'utf8').digest('base64')}'`;

const { outputFiles } = await build({
  entryPoints: ['src/app.js'],
  bundle: true,
  format: 'iife',
  target: ['es2022'],
  minify: false,          // keep it readable: you should be able to audit what you serve
  legalComments: 'inline',
  write: false,
  define: { __RELAY__: JSON.stringify(relayHttp), __GATE__: JSON.stringify(gate) },
});
const script = outputFiles[0].text.replace(/<\/script/gi, '<\\/script');
const style = await readFile('src/style.css', 'utf8');

const csp = [
  "default-src 'none'",
  `script-src ${sha(script)}`,
  `style-src ${sha(style)}`,
  'img-src data:',
  'media-src mediastream: blob:',
  `connect-src ${relayHttp} ${relayWs}`,
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

const html = (await readFile('src/index.html', 'utf8'))
  .replace('__CSP__', () => csp)
  .replace('__STYLE__', () => style)
  .replace('__SCRIPT__', () => script);

if (/__(CSP|STYLE|SCRIPT)__/.test(html)) throw new Error('unreplaced placeholder');
await mkdir('dist', { recursive: true });
await writeFile('dist/index.html', html);
console.log(`relay ${relayHttp}\ndist/index.html  ${(html.length / 1024).toFixed(1)} KB  sha256=${createHash('sha256').update(html).digest('hex')}`);
