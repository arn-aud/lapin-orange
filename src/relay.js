// Dumb relay over ntfy.sh: it only ever sees opaque frames on a random topic.
// cache=no  -> ntfy does not store messages, only forwards to live subscribers.
// firebase=no -> not forwarded to Google's push service.
// The POST is a CORS "simple request" (text/plain body, no custom headers): no preflight.

// Set at build time (RELAY_URL env var); CSP connect-src is generated from the same value.
export const RELAY_BASE = __RELAY__;

export class Relay {
  constructor(topic, { onFrame, onStatus, base = RELAY_BASE } = {}) {
    this.topic = topic;
    this.base = base;
    this.onFrame = onFrame || (() => {});
    this.onStatus = onStatus || (() => {});
    this.ws = null;
    this.closed = false;
    this.retry = 0;
  }

  connect() {
    if (this.closed) return;
    this.onStatus('connecting');
    const ws = new WebSocket(this.base.replace(/^http/, 'ws') + `/${this.topic}/ws`);
    this.ws = ws;
    ws.onopen = () => { this.retry = 0; };
    ws.onmessage = (ev) => {
      let d;
      try { d = JSON.parse(ev.data); } catch { return; }
      if (d.event === 'open') this.onStatus('online');
      else if (d.event === 'message' && typeof d.message === 'string') this.onFrame(d.message);
    };
    ws.onclose = () => {
      if (this.ws !== ws || this.closed) return;
      this.onStatus('offline');
      const delay = Math.min(15000, 500 * 2 ** this.retry++);
      setTimeout(() => this.connect(), delay);
    };
    ws.onerror = () => {};
  }

  async publish(frame) {
    const r = await fetch(`${this.base}/${this.topic}?cache=no&firebase=no`, {
      method: 'POST',
      body: frame,
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      cache: 'no-store',
    });
    if (!r.ok) throw new Error(`relay HTTP ${r.status}`);
  }

  close() {
    this.closed = true;
    if (this.ws) this.ws.close();
    this.ws = null;
  }
}
