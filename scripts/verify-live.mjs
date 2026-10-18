// Usage: npm run verify -- https://<you>.github.io/clip/
// Rebuilds locally and checks the deployed page is byte-identical. Run it from a trusted machine.
import { execSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const url = process.argv[2];
if (!url) { console.error('usage: npm run verify -- <deployed url>'); process.exit(2); }
execSync('node build.mjs', { stdio: 'inherit' });
const h = (b) => createHash('sha256').update(b).digest('hex');
const local = h(await readFile('dist/index.html'));
const res = await fetch(url, { cache: 'no-store' });
const remote = h(Buffer.from(await res.arrayBuffer()));
console.log(`local  ${local}\nremote ${remote}`);
if (local !== remote) { console.error('MISMATCH: deployed page differs from source build'); process.exit(1); }
console.log('OK: deployed page matches source build');
