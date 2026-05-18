// Battonaasje — private gate verification Worker
// Deploy to Cloudflare Workers.
//
// Required secrets (set with wrangler secret put):
//   GATE_CODE   — the private access code visitors type
//   LOG_SECRET  — a password that protects the /logs viewer
//
// Required KV binding (see wrangler.gate.toml):
//   ACCESS_LOG  — stores one entry per login attempt, 30-day TTL

const ALLOWED_ORIGINS = [
  'https://battonaasje.nl',
  'https://www.battonaasje.nl',
  'http://localhost:3456',
];

// ─── Rate limiting ────────────────────────────────────────────────────────────
// In-memory store resets per isolate restart — good enough for brute-force.
const attempts = new Map();
const WINDOW_MS    = 60_000; // 1 minute
const MAX_ATTEMPTS = 10;     // per IP per window

function isRateLimited(ip) {
  const now   = Date.now();
  const entry = attempts.get(ip);
  if (!entry || now > entry.resetAt) {
    attempts.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return false;
  }
  entry.count++;
  return entry.count > MAX_ATTEMPTS;
}

// ─── CORS ─────────────────────────────────────────────────────────────────────
function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age':       '86400',
  };
}

// ─── KV logging ──────────────────────────────────────────────────────────────
// Key: log:<16-char-padded-ms-timestamp>
// Value: JSON — { ts, ip, country, ua, ok }
// TTL: 30 days
async function logAttempt(env, ip, country, ua, ok) {
  if (!env.ACCESS_LOG) return; // KV not bound (local dev without binding)
  const ts  = Date.now();
  const key = `log:${String(ts).padStart(16, '0')}`;
  const val = JSON.stringify({
    ts,
    ip,
    country: country || '??',
    ua:      (ua || '').slice(0, 250),
    ok,
  });
  try {
    await env.ACCESS_LOG.put(key, val, { expirationTtl: 30 * 24 * 60 * 60 });
  } catch (err) {
    // Swallow — never break /verify because logging failed
    console.error('logAttempt failed', err);
  }
}

// ─── /logs HTML viewer ────────────────────────────────────────────────────────
async function handleLogs(request, env) {
  const logSecret = env.LOG_SECRET || '';
  const url       = new URL(request.url);
  const provided  = url.searchParams.get('secret') || '';

  if (!logSecret || provided !== logSecret) {
    return new Response('Unauthorized', { status: 401 });
  }

  // List up to 200 most-recent keys (keys are ms-timestamp-sorted ascending)
  let keys = [];
  try {
    const listed = await env.ACCESS_LOG.list({ prefix: 'log:', limit: 1000 });
    keys = listed.keys.slice(-200).reverse(); // newest first
  } catch {
    return new Response('KV error', { status: 500 });
  }

  // Fetch all values in parallel
  const entries = await Promise.all(
    keys.map(async ({ name }) => {
      try {
        const raw = await env.ACCESS_LOG.get(name);
        return raw ? JSON.parse(raw) : null;
      } catch {
        return null;
      }
    })
  );

  const rows = entries
    .filter(Boolean)
    .map((e) => {
      const date = new Date(e.ts).toLocaleString('nl-NL', { timeZone: 'Europe/Amsterdam' });
      const ok   = e.ok
        ? '<td style="color:#2a7a3b;font-weight:600">✓ OK</td>'
        : '<td style="color:#a05040;font-weight:600">✗ Mislukt</td>';
      const ua   = e.ua.replace(/</g, '&lt;');
      return `<tr>
        <td>${date}</td>
        ${ok}
        <td>${e.ip}</td>
        <td>${e.country}</td>
        <td style="font-size:11px;color:#666;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${ua}</td>
      </tr>`;
    })
    .join('\n');

  const total   = entries.filter(Boolean).length;
  const success = entries.filter((e) => e?.ok).length;
  const failed  = total - success;

  const html = `<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Battonaasje — Toegangslog</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; background: #f2ede4; color: #1a1714; padding: 48px 32px; }
  h1 { font-size: 22px; letter-spacing: 6px; text-transform: uppercase; margin-bottom: 8px; }
  .sub { font-size: 11px; letter-spacing: 2px; color: #8c8478; margin-bottom: 32px; }
  .stats { display: flex; gap: 24px; margin-bottom: 32px; flex-wrap: wrap; }
  .stat { background: #e8e2d6; padding: 14px 20px; min-width: 120px; }
  .stat-label { font-size: 9px; letter-spacing: 3px; text-transform: uppercase; color: #8c8478; margin-bottom: 6px; }
  .stat-value { font-size: 28px; color: #1a1714; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; font-size: 9px; letter-spacing: 3px; text-transform: uppercase; color: #8c8478; border-bottom: 1px solid #c8c0b0; padding: 10px 12px; }
  td { padding: 10px 12px; border-bottom: 1px solid #e8e2d6; vertical-align: top; }
  tr:hover td { background: #ede8df; }
  .empty { padding: 48px; text-align: center; color: #8c8478; font-style: italic; }
</style>
</head>
<body>
  <h1>Battonaasje</h1>
  <div class="sub">Toegangslog — laatste ${total} pogingen (max 200, bewaard 30 dagen)</div>
  <div class="stats">
    <div class="stat"><div class="stat-label">Totaal</div><div class="stat-value">${total}</div></div>
    <div class="stat"><div class="stat-label">Geslaagd</div><div class="stat-value" style="color:#2a7a3b">${success}</div></div>
    <div class="stat"><div class="stat-label">Mislukt</div><div class="stat-value" style="color:#a05040">${failed}</div></div>
  </div>
  ${total === 0 ? '<div class="empty">Nog geen pogingen gelogd.</div>' : `
  <table>
    <thead>
      <tr>
        <th>Tijdstip (AMS)</th>
        <th>Uitkomst</th>
        <th>IP-adres</th>
        <th>Land</th>
        <th>Browser</th>
      </tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>`}
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// ─── Main handler ─────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const url    = new URL(request.url);

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // Audit log viewer
    if (request.method === 'GET' && url.pathname === '/logs') {
      return handleLogs(request, env);
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    // Only /verify accepts POST
    if (url.pathname !== '/verify' && url.pathname !== '/') {
      return new Response('Not Found', { status: 404 });
    }

    const ip      = request.headers.get('CF-Connecting-IP') || 'unknown';
    const country = request.headers.get('CF-IPCountry')     || '??';
    const ua      = request.headers.get('User-Agent')       || '';

    if (isRateLimited(ip)) {
      await logAttempt(env, ip, country, ua, false);
      return new Response(JSON.stringify({ ok: false, error: 'too_many_attempts' }), {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': '60',
          ...corsHeaders(origin),
        },
      });
    }

    let code;
    try {
      const body = await request.json();
      code = (body.code || '').trim().toUpperCase();
    } catch {
      return new Response(JSON.stringify({ ok: false }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    const gateCode = (env.GATE_CODE || '').toUpperCase();
    const valid    = code.length > 0 && code === gateCode;

    // Log the attempt — must await so the KV write completes before
    // the Worker isolate is allowed to terminate.
    await logAttempt(env, ip, country, ua, valid);

    return new Response(JSON.stringify({ ok: valid }), {
      status: valid ? 200 : 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  },
};
