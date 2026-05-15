/**
 * IronRelay — Cloudflare Worker exit node
 *
 * Receives POST bodies containing concatenated binary frames from the GS relay.
 * Maintains a session map (module-level, lives for the isolate lifetime).
 * Dials real TCP connections using the `cloudflare:sockets` API.
 *
 * Frame wire format (21-byte header + payload):
 *   [1B cmd] [16B session_id] [4B payload_len big-endian] [N bytes payload]
 *
 * Commands from client:
 *   SYN  0x01  payload = "host:port"   open TCP connection
 *   DATA 0x02  payload = raw bytes     send bytes to remote
 *   FIN  0x03  payload = empty         close TCP connection
 *
 * Commands to client (in response body):
 *   ACK  0x04  payload = raw bytes     bytes received from remote
 *   FIN  0x03  payload = empty         remote closed / error
 */

import { connect } from 'cloudflare:sockets';

const CMD_SYN  = 0x01;
const CMD_DATA = 0x02;
const CMD_FIN  = 0x03;
const CMD_ACK  = 0x04;
const SESSION_ID_LEN = 16;
const HEADER_SIZE = 1 + SESSION_ID_LEN + 4; // 21 bytes

// Module-level session store.
// Key: hex session_id string  Value: { socket, writer, readBuf: Uint8Array[] }
const sessions = new Map();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/healthz') {
      return Response.json({ ok: true, sessions: sessions.size });
    }

    if (request.method !== 'POST' || url.pathname !== '/tunnel') {
      return new Response('Not Found', { status: 404 });
    }

    // Auth check.
    const token = env.RELAY_TOKEN || '';
    if (token && request.headers.get('X-Relay-Token') !== token) {
      return new Response('Unauthorized', { status: 401 });
    }

    const body = await request.arrayBuffer();
    const inFrames = decodeFrames(new Uint8Array(body));

    // Process each inbound frame.
    const pendingReads = [];
    for (const f of inFrames) {
      const key = hexID(f.sessionID);
      switch (f.cmd) {
        case CMD_SYN: {
          const target = new TextDecoder().decode(f.payload);
          const [host, portStr] = splitHostPort(target);
          const port = parseInt(portStr, 10);
          try {
            const socket = connect({ hostname: host, port });
            const writer = socket.writable.getWriter();
            const entry = { socket, writer, readBuf: [] };
            sessions.set(key, entry);
            // Start draining the readable side into readBuf.
            drainReadable(socket.readable, entry);
          } catch (e) {
            // If connect throws synchronously, queue a FIN back.
            pendingReads.push(finFrame(f.sessionID));
          }
          break;
        }
        case CMD_DATA: {
          const entry = sessions.get(key);
          if (entry) {
            // write is best-effort; if the socket is closed, swallow the error.
            entry.writer.write(f.payload).catch(() => {});
          }
          break;
        }
        case CMD_FIN: {
          const entry = sessions.get(key);
          if (entry) {
            entry.writer.close().catch(() => {});
            sessions.delete(key);
          }
          break;
        }
      }
    }

    // Give newly opened sockets a short window to receive initial data
    // (e.g., TLS ServerHello) before we respond. This dramatically reduces
    // round-trips for request/response protocols like HTTPS.
    await sleep(20);

    // Collect any buffered ACK bytes from all sessions that sent us frames.
    const seenKeys = new Set(inFrames.map(f => hexID(f.sessionID)));
    const outFrames = [...pendingReads];
    for (const key of seenKeys) {
      const entry = sessions.get(key);
      if (!entry) continue;
      if (entry.readBuf.length > 0) {
        const combined = concatUint8Arrays(entry.readBuf);
        entry.readBuf = [];
        const sid = unhexID(key);
        outFrames.push(encodeFrame(CMD_ACK, sid, combined));
      }
      if (entry.closed) {
        sessions.delete(key);
        const sid = unhexID(key);
        outFrames.push(finFrame(sid));
      }
    }

    if (outFrames.length === 0) {
      return new Response(null, { status: 204 });
    }

    const responseBody = concatUint8Arrays(outFrames);
    return new Response(responseBody, {
      status: 200,
      headers: { 'Content-Type': 'application/octet-stream' },
    });
  },
};

// ---------------------------------------------------------------------------
// drainReadable — continuously read from socket.readable into entry.readBuf
// ---------------------------------------------------------------------------
async function drainReadable(readable, entry) {
  try {
    const reader = readable.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        entry.readBuf.push(new Uint8Array(value));
      }
    }
  } catch (_) {
    // socket error or closed
  }
  entry.closed = true;
}

// ---------------------------------------------------------------------------
// Frame encode / decode
// ---------------------------------------------------------------------------
function decodeFrames(buf) {
  const frames = [];
  let offset = 0;
  while (offset + HEADER_SIZE <= buf.length) {
    const cmd = buf[offset];
    const sessionID = buf.slice(offset + 1, offset + 1 + SESSION_ID_LEN);
    const payloadLen =
      (buf[offset + 17] << 24) |
      (buf[offset + 18] << 16) |
      (buf[offset + 19] << 8)  |
       buf[offset + 20];
    offset += HEADER_SIZE;
    if (offset + payloadLen > buf.length) break;
    const payload = buf.slice(offset, offset + payloadLen);
    offset += payloadLen;
    frames.push({ cmd, sessionID, payload });
  }
  return frames;
}

function encodeFrame(cmd, sessionID, payload) {
  const out = new Uint8Array(HEADER_SIZE + payload.length);
  out[0] = cmd;
  out.set(sessionID, 1);
  const len = payload.length;
  out[17] = (len >>> 24) & 0xff;
  out[18] = (len >>> 16) & 0xff;
  out[19] = (len >>>  8) & 0xff;
  out[20] =  len         & 0xff;
  out.set(payload, HEADER_SIZE);
  return out;
}

function finFrame(sessionID) {
  return encodeFrame(CMD_FIN, sessionID, new Uint8Array(0));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function hexID(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function unhexID(hex) {
  const arr = new Uint8Array(SESSION_ID_LEN);
  for (let i = 0; i < SESSION_ID_LEN; i++) {
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

function splitHostPort(target) {
  const lastColon = target.lastIndexOf(':');
  return [target.slice(0, lastColon), target.slice(lastColon + 1)];
}

function concatUint8Arrays(arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
