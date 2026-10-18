// Minimal static server for dist/ (tests only).
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';

const port = Number(process.env.PORT || 4173);
createServer(async (req, res) => {
  const path = new URL(req.url, 'http://x').pathname;
  if (path !== '/' && path !== '/index.html') {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(await readFile('dist/index.html'));
}).listen(port, '127.0.0.1', () => console.log(`serving dist on http://localhost:${port}`));
