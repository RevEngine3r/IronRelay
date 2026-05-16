/**
 * IronRelay — Cloudflare Worker relay server.
 *
 * Endpoints:
 *   POST /tunnel  — forward encrypted batch to VPS; body is AES-256-GCM sealed
 *                   by the client using PSK_HEX (same key as tunnel_key).
 *   GET  /healthz — VPS health proxy
 *   GET  /info    — worker metadata
 *
 * Required env vars (set via wrangler secret or wrangler.toml [vars]):
 *   VPS_URL        full URL of your VPS server, e.g. http://1.2.3.4:8443
 *   PSK_HEX        64 hex chars (32 bytes) — MUST match client tunnel_key
 *
 * Optional:
 *   SHARED_SECRET  legacy header-based token (X-Relay-Auth); prefer PSK_HEX
 *   TIMEOUT_MS     per-request VPS timeout in ms (default 10000)
 */

const TUNNEL_PATH  = '/tunnel';
const HEALTHZ_PATH = '/healthz';
const INFO_PATH    = '/info';
const MAX_BODY     = 50 * 1024 * 1024; // 50 MB
const NONCE_LEN    = 12;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'POST' && url.pathname === TUNNEL_PATH) {
      return handleTunnel(request, env);
    }
    if (request.method === 'GET' && url.pathname === HEALTHZ_PATH) {
      return handleHealthz(request, env);
    }
    if (request.method === 'GET' && url.pathname === INFO_PATH) {
      return handleInfo(env);
    }
    return new Response('not found', { status: 404 });
  },
};

// ---------------------------------------------------------------------------
// AES-256-GCM helpers (matches client psk.SealRaw / psk.OpenRaw)
// Wire format: [ 12-byte nonce | ciphertext+16-byte tag ]
// ---------------------------------------------------------------------------
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

async function importAES(pskHex) {
  return crypto.subtle.importKey(
    'raw', hexToBytes(pskHex),
    { name: 'AES-GCM' },
    false, ['decrypt', 'encrypt']
  );
}

async function aesOpen(key, buf) {
  if (buf.byteLength < NONCE_LEN + 16) throw new Error('ciphertext too short');
  const nonce = buf.slice(0, NONCE_LEN);
  const ct    = buf.slice(NONCE_LEN);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct);
}

async function aesSeal(key, plain) {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const ct    = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plain);
  const out   = new Uint8Array(NONCE_LEN + ct.byteLength);
  out.set(nonce);
  out.set(new Uint8Array(ct), NONCE_LEN);
  return out.buffer;
}

// ---------------------------------------------------------------------------
// /tunnel handler
// ---------------------------------------------------------------------------
async function handleTunnel(request, env) {
  const vpsURL = env.VPS_URL;
  if (!vpsURL) {
    return new Response('VPS_URL not configured', { status: 503 });
  }

  // Legacy shared-secret check (header-based, no crypto)
  if (env.SHARED_SECRET) {
    const got = request.headers.get('X-Relay-Auth') || '';
    if (got !== env.SHARED_SECRET) {
      return new Response('forbidden', { status: 403 });
    }
  }

  // Read body (size-gated)
  const bodyBuf = await readBody(request);
  if (bodyBuf === null) {
    return new Response('request too large', { status: 413 });
  }

  // PSK mode: unseal the AES-GCM body, forward plaintext to VPS, re-seal response.
  // Authentication is implicit: a wrong key will cause decrypt to throw.
  if (env.PSK_HEX) {
    let plain;
    try {
      const aesKey = await importAES(env.PSK_HEX);
      plain = await aesOpen(aesKey, bodyBuf);
    } catch (e) {
      return new Response('decrypt failed — wrong PSK or tampered body', { status: 403 });
    }

    // Forward plaintext to VPS, seal VPS response back to client
    const vpsResp = await forwardToVPS(vpsURL, plain, env);
    if (!vpsResp.ok) {
      return new Response(await vpsResp.text(), { status: vpsResp.status });
    }
    const vpsBody = await vpsResp.arrayBuffer();
    if (vpsBody.byteLength === 0) {
      return new Response(null, { status: 204 });
    }
    const sealKey = await importAES(env.PSK_HEX);
    const sealed  = await aesSeal(sealKey, vpsBody);
    return new Response(sealed, {
      status: 200,
      headers: { 'Content-Type': 'application/octet-stream' },
    });
  }

  // No PSK configured — pass-through (legacy mode)
  const vpsResp = await forwardToVPS(vpsURL, bodyBuf, env);
  return vpsResp;
}

async function forwardToVPS(vpsURL, body, env) {
  const timeoutMs = parseInt(env.TIMEOUT_MS || '10000', 10);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(`${vpsURL}/tunnel`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function readBody(request) {
  const ct = parseInt(request.headers.get('content-length') || '0', 10);
  if (ct > MAX_BODY) return null;
  const buf = await request.arrayBuffer();
  if (buf.byteLength > MAX_BODY) return null;
  return buf;
}

// ---------------------------------------------------------------------------
// /healthz handler
// ---------------------------------------------------------------------------
async function handleHealthz(request, env) {
  const vpsURL = env.VPS_URL;
  if (!vpsURL) return new Response(JSON.stringify({ ok: true, vps: 'not configured' }), {
    headers: { 'Content-Type': 'application/json' },
  });
  try {
    const r = await fetch(`${vpsURL}/healthz`, { cf: { cacheTtl: 0 } });
    const body = await r.text();
    return new Response(body, { status: r.status, headers: { 'Content-Type': 'application/json' } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e.message }), {
      status: 502, headers: { 'Content-Type': 'application/json' },
    });
  }
}

// ---------------------------------------------------------------------------
// /info handler
// ---------------------------------------------------------------------------
function handleInfo(env) {
  return new Response(JSON.stringify({
    relay:   'IronRelay CF Worker',
    version: '2.0.0',
    vps:     env.VPS_URL ? 'configured' : 'not configured',
    psk:     env.PSK_HEX ? 'configured' : 'not configured (legacy mode)',
  }, null, 2), { headers: { 'Content-Type': 'application/json' } });
}
