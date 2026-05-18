// Battonaasje — private gate verification + pageview analytics Worker
// Deploy to Cloudflare Workers.
//
// Required secrets (set with wrangler secret put, or via dashboard):
//   GATE_CODE     — the private access code visitors type
//   LOG_SECRET    — a password that protects the /logs and /stats viewers
//
// Required KV binding (see wrangler.gate.toml):
//   ACCESS_LOG  — stores both access attempts (log:*) and pageviews (pv:*)
//
// Endpoints:
//   POST /verify           — verifies GATE_CODE
//   POST /track            — records a pageview (body: { page })
//   GET  /logs?secret=...  — HTML viewer of last 200 access attempts
//   GET  /stats?secret=... — HTML viewer of pageview analytics

const ALLOWED_ORIGINS = [
  'https://battonaasje.nl',
  'https://www.battonaasje.nl',
  'http://localhost:3456',
];

// ─── Rate limiting ────────────────────────────────────────────────────────────
const verifyAttempts = new Map();
const trackAttempts  = new Map();
const VERIFY_WINDOW_MS    = 60_000;
const VERIFY_MAX_ATTEMPTS = 10;
const TRACK_WINDOW_MS     = 60_000;
const TRACK_MAX_ATTEMPTS  = 60;   // 1 per second average — generous

function isRateLimited(store, ip, max, windowMs) {
  const now   = Date.now();
  const entry = store.get(ip);
  if (!entry || now > entry.resetAt) {
    store.set(ip, { count: 1, resetAt: now + windowMs });
    return false;
  }
  entry.count++;
  return entry.count > max;
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

// ─── KV: access log ──────────────────────────────────────────────────────────
// Key:   log:<16-char-padded-ms-timestamp>
// Value: JSON — { ts, ip, country, ua, ok }
// TTL:   30 days
async function logAttempt(env, ip, country, ua, ok) {
  if (!env.ACCESS_LOG) return;
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
    console.error('logAttempt failed', err);
  }
}

// ─── KV: pageview counters ───────────────────────────────────────────────────
// Key:   pv:YYYY-MM-DD:<path>
// Value: integer count as string
// TTL:   90 days
//
// Race conditions on read-modify-write are acceptable for analytics —
// numbers are approximate by nature.
function sanitizePath(p) {
  let s = (p || '/').trim().slice(0, 80);
  // Allow only: letters, digits, /, -, _
  s = s.replace(/[^a-zA-Z0-9/_-]/g, '');
  if (!s.startsWith('/')) s = '/' + s;
  return s || '/';
}

function todayISO() {
  return new Date().toISOString().slice(0, 10);
}

async function recordPageview(env, page) {
  if (!env.ACCESS_LOG) return;
  const date = todayISO();
  const key  = `pv:${date}:${page}`;
  try {
    const current = await env.ACCESS_LOG.get(key);
    const next    = (parseInt(current, 10) || 0) + 1;
    await env.ACCESS_LOG.put(key, String(next), { expirationTtl: 90 * 24 * 60 * 60 });
  } catch (err) {
    console.error('recordPageview failed', err);
  }
}

// ─── KV: stock management ────────────────────────────────────────────────────
// Key:   stock:<slug>
// Value: integer count as string (no TTL — manual management)
//
// KNOWN_WINES is the canonical list of wines that the /voorraad admin shows.
// Keep this in sync with payments.js CATALOG. Adding a wine = add entry here.
const KNOWN_WINES = [
  { slug: 'frerejean-freres-champagne',          name: 'Frerejean Frères Premier Cru' },
  { slug: 'chablis-grand-cru-blanchot-1991',     name: 'Defaix Chablis Grand Cru Blanchot 1991' },
  { slug: 'massolino-barolo-2019-magnum',        name: 'Massolino Barolo 2019 Magnum' },
];

const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,80}$/;

async function getStockMap(env) {
  if (!env.ACCESS_LOG) return {};
  const map = {};
  for (const w of KNOWN_WINES) {
    const raw = await env.ACCESS_LOG.get(`stock:${w.slug}`);
    map[w.slug] = raw === null ? null : (parseInt(raw, 10) || 0);
  }
  return map;
}

async function setStock(env, slug, count) {
  if (!env.ACCESS_LOG) return;
  await env.ACCESS_LOG.put(`stock:${slug}`, String(count));
}

// ── GET /stock — public JSON read ────────────────────────────────────────────
async function handleStockRead(request, env) {
  const origin = request.headers.get('Origin') || '';
  const stock  = await getStockMap(env);
  return new Response(JSON.stringify({ ok: true, stock }), {
    status: 200,
    headers: {
      'Content-Type':  'application/json',
      'Cache-Control': 'no-store',
      ...corsHeaders(origin),
    },
  });
}

// ── GET/POST /voorraad — admin HTML + update ─────────────────────────────────
async function handleVoorraadAdmin(request, env) {
  const url      = new URL(request.url);
  const provided = url.searchParams.get('secret') || '';
  if (!env.LOG_SECRET || provided !== env.LOG_SECRET) {
    return new Response('Unauthorized', { status: 401 });
  }

  // POST: update one wine
  if (request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch {
      return new Response(JSON.stringify({ ok: false, error: 'invalid_body' }), {
        status: 400, headers: { 'Content-Type': 'application/json' },
      });
    }
    const slug  = String(body.slug || '');
    const count = parseInt(body.count, 10);
    if (!SLUG_RE.test(slug))         return new Response(JSON.stringify({ ok: false, error: 'invalid_slug' }),  { status: 400, headers: { 'Content-Type': 'application/json' } });
    if (isNaN(count) || count < 0)   return new Response(JSON.stringify({ ok: false, error: 'invalid_count' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    if (count > 9999)                return new Response(JSON.stringify({ ok: false, error: 'too_high' }),      { status: 400, headers: { 'Content-Type': 'application/json' } });
    await setStock(env, slug, count);
    return new Response(JSON.stringify({ ok: true, slug, count }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    });
  }

  // GET: render admin HTML
  const stock = await getStockMap(env);
  const rows = KNOWN_WINES.map((w) => {
    const current = stock[w.slug];
    const display = current === null ? '—' : current;
    const status =
      current === null ? '<span style="color:#8c8478">niet ingesteld</span>' :
      current === 0    ? '<span style="color:#a05040;font-weight:600">UITVERKOCHT</span>' :
      current <= 2     ? '<span style="color:#c68b2c;font-weight:600">LAAG</span>' :
                         '<span style="color:#2a7a3b;font-weight:600">OK</span>';
    return `<tr>
      <td><div style="font-weight:600">${w.name}</div><div style="font-size:11px;color:#8c8478;margin-top:2px">${w.slug}</div></td>
      <td style="text-align:center;font-size:22px;font-family:'Cormorant Garamond',serif;font-style:italic">${display}</td>
      <td>${status}</td>
      <td>
        <form class="stock-form" data-slug="${w.slug}" onsubmit="return updateStock(event)" style="display:flex;gap:8px">
          <input type="number" min="0" max="9999" value="${current === null ? '' : current}" required style="width:90px;padding:8px;font-family:'Courier Prime',monospace;font-size:14px;border:1px solid #c8c0b0;background:#fff">
          <button type="submit" style="padding:8px 16px;background:#1a1714;color:#f2ede4;border:none;font-family:'Courier Prime',monospace;font-size:10px;letter-spacing:2px;text-transform:uppercase;cursor:pointer">Bijwerken</button>
        </form>
      </td>
    </tr>`;
  }).join('\n');

  const html = `<!DOCTYPE html>
<html lang="nl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Battonaasje — Voorraad</title>
${SHARED_CSS}
<style>
  td { vertical-align: middle; }
  .saved-flash { color: #2a7a3b; font-size: 10px; letter-spacing: 2px; opacity: 0; transition: opacity 0.3s; }
  .saved-flash.visible { opacity: 1; }
</style>
</head><body>
<div class="topbar">
  <h1>Battonaasje</h1>
  <nav class="topnav">
    <a href="/logs?secret=${encodeURIComponent(provided)}">Toegangslog</a>
    <a href="/stats?secret=${encodeURIComponent(provided)}">Bezoekers</a>
    <a href="/voorraad?secret=${encodeURIComponent(provided)}" class="active">Voorraad</a>
  </nav>
</div>
<div class="sub">Voorraad-beheer · wijzigingen zijn direct zichtbaar op battonaasje.nl</div>

<table>
  <thead><tr><th>Wijn</th><th style="text-align:center">Voorraad</th><th>Status</th><th>Aanpassen</th></tr></thead>
  <tbody>${rows}</tbody>
</table>

<p style="margin-top:32px;font-size:11px;color:#8c8478;letter-spacing:1px;line-height:1.8">
  Tip: zet voorraad op <strong>0</strong> om de bestelknop te deactiveren ("Uitverkocht").<br>
  Bij <strong>1 of 2</strong> flessen toont de site automatisch "Laatste flessen".<br>
  Bij <strong>—</strong> (niet ingesteld) toont de site géén voorraad-badge.
</p>

<script>
async function updateStock(e) {
  e.preventDefault();
  var form = e.target;
  var slug = form.dataset.slug;
  var count = parseInt(form.querySelector('input').value);
  var btn = form.querySelector('button');
  btn.disabled = true;
  btn.textContent = '...';
  try {
    var res = await fetch(location.pathname + location.search, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slug: slug, count: count })
    });
    var data = await res.json();
    if (!data.ok) throw new Error(data.error || 'error');
    btn.textContent = '✓ Opgeslagen';
    setTimeout(function() { location.reload(); }, 600);
  } catch (err) {
    btn.disabled = false;
    btn.textContent = 'Fout — opnieuw';
  }
  return false;
}
</script>
</body></html>`;
  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

// ─── /logs HTML viewer ────────────────────────────────────────────────────────
async function handleLogs(request, env) {
  const provided = new URL(request.url).searchParams.get('secret') || '';
  if (!env.LOG_SECRET || provided !== env.LOG_SECRET) {
    return new Response('Unauthorized', { status: 401 });
  }

  let keys = [];
  try {
    const listed = await env.ACCESS_LOG.list({ prefix: 'log:', limit: 1000 });
    keys = listed.keys.slice(-200).reverse();
  } catch {
    return new Response('KV error', { status: 500 });
  }

  const entries = await Promise.all(
    keys.map(async ({ name }) => {
      try {
        const raw = await env.ACCESS_LOG.get(name);
        return raw ? JSON.parse(raw) : null;
      } catch { return null; }
    })
  );

  const rows = entries.filter(Boolean).map((e) => {
    const date = new Date(e.ts).toLocaleString('nl-NL', { timeZone: 'Europe/Amsterdam' });
    const ok   = e.ok
      ? '<td style="color:#2a7a3b;font-weight:600">✓ OK</td>'
      : '<td style="color:#a05040;font-weight:600">✗ Mislukt</td>';
    const ua   = e.ua.replace(/</g, '&lt;');
    return `<tr><td>${date}</td>${ok}<td>${e.ip}</td><td>${e.country}</td><td class="ua">${ua}</td></tr>`;
  }).join('\n');

  const total   = entries.filter(Boolean).length;
  const success = entries.filter((e) => e?.ok).length;
  const failed  = total - success;

  const html = `<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Battonaasje — Toegangslog</title>
${SHARED_CSS}
</head>
<body>
  <div class="topbar">
    <h1>Battonaasje</h1>
    <nav class="topnav">
      <a href="/logs?secret=${encodeURIComponent(provided)}" class="active">Toegangslog</a>
      <a href="/stats?secret=${encodeURIComponent(provided)}">Bezoekers</a>
      <a href="/voorraad?secret=${encodeURIComponent(provided)}">Voorraad</a>
    </nav>
  </div>
  <div class="sub">Toegangslog — laatste ${total} pogingen (max 200, bewaard 30 dagen)</div>
  <div class="stats">
    <div class="stat"><div class="stat-label">Totaal</div><div class="stat-value">${total}</div></div>
    <div class="stat"><div class="stat-label">Geslaagd</div><div class="stat-value" style="color:#2a7a3b">${success}</div></div>
    <div class="stat"><div class="stat-label">Mislukt</div><div class="stat-value" style="color:#a05040">${failed}</div></div>
  </div>
  ${total === 0 ? '<div class="empty">Nog geen pogingen gelogd.</div>' : `
  <table>
    <thead><tr><th>Tijdstip (AMS)</th><th>Uitkomst</th><th>IP-adres</th><th>Land</th><th>Browser</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`}
</body></html>`;

  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

// ─── /stats HTML viewer ──────────────────────────────────────────────────────
async function handleStats(request, env) {
  const provided = new URL(request.url).searchParams.get('secret') || '';
  if (!env.LOG_SECRET || provided !== env.LOG_SECRET) {
    return new Response('Unauthorized', { status: 401 });
  }

  // Page through all pv:* keys (max 1000 per list call)
  let allKeys = [];
  let cursor;
  try {
    do {
      const opts = { prefix: 'pv:', limit: 1000 };
      if (cursor) opts.cursor = cursor;
      const listed = await env.ACCESS_LOG.list(opts);
      allKeys = allKeys.concat(listed.keys);
      cursor = listed.list_complete ? null : listed.cursor;
    } while (cursor);
  } catch {
    return new Response('KV error', { status: 500 });
  }

  // Fetch all counts in parallel
  const entries = await Promise.all(
    allKeys.map(async ({ name }) => {
      const raw = await env.ACCESS_LOG.get(name);
      const parts = name.split(':'); // [ "pv", "YYYY-MM-DD", "/path" ]
      const date  = parts[1];
      const path  = parts.slice(2).join(':') || '/';
      return { date, path, count: parseInt(raw, 10) || 0 };
    })
  );

  const today    = todayISO();
  const week     = new Set();
  const weekDate = new Date();
  for (let i = 0; i < 7; i++) {
    week.add(weekDate.toISOString().slice(0, 10));
    weekDate.setUTCDate(weekDate.getUTCDate() - 1);
  }

  // Aggregate totals
  let totalAll   = 0;
  let totalToday = 0;
  let totalWeek  = 0;
  const perPage  = new Map();   // path -> count
  const perDay   = new Map();   // date -> count

  for (const e of entries) {
    totalAll += e.count;
    if (e.date === today)   totalToday += e.count;
    if (week.has(e.date))   totalWeek  += e.count;
    perPage.set(e.path, (perPage.get(e.path) || 0) + e.count);
    perDay.set(e.date,  (perDay.get(e.date)  || 0) + e.count);
  }

  const topPages = [...perPage.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 50);

  // Build last 30 days (in chronological order)
  const days = [];
  const cursorDate = new Date();
  for (let i = 29; i >= 0; i--) {
    const d = new Date(cursorDate);
    d.setUTCDate(cursorDate.getUTCDate() - i);
    const iso = d.toISOString().slice(0, 10);
    days.push({ date: iso, count: perDay.get(iso) || 0 });
  }
  const maxDayCount = Math.max(1, ...days.map((d) => d.count));

  const pagesRows = topPages.length === 0
    ? '<tr><td colspan="2" class="empty-cell">Nog geen bezoekers geregistreerd.</td></tr>'
    : topPages.map(([path, count]) => {
        const label = path.replace(/</g, '&lt;');
        return `<tr><td><a href="https://battonaasje.nl${path}" target="_blank" rel="noopener">${label}</a></td><td style="text-align:right;font-weight:600">${count}</td></tr>`;
      }).join('\n');

  const chartBars = days.map((d) => {
    const h = Math.round((d.count / maxDayCount) * 100);
    const dayLabel = d.date.slice(8); // DD
    const isToday = d.date === today;
    return `<div class="bar-wrap" title="${d.date}: ${d.count} bezoeken">
      <div class="bar-count">${d.count || ''}</div>
      <div class="bar" style="height:${h}%;${isToday ? 'background:#1a1714' : ''}"></div>
      <div class="bar-label">${dayLabel}</div>
    </div>`;
  }).join('\n');

  const html = `<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Battonaasje — Bezoekers</title>
${SHARED_CSS}
<style>
  .chart { display: flex; align-items: flex-end; gap: 4px; height: 200px; background: #ede8df; padding: 20px 16px 8px; margin-bottom: 8px; border-bottom: 1px solid #c8c0b0; }
  .bar-wrap { flex: 1; display: flex; flex-direction: column; justify-content: flex-end; align-items: center; height: 100%; min-width: 0; }
  .bar { width: 100%; max-width: 24px; background: #3a3528; min-height: 2px; transition: opacity 0.15s; }
  .bar-wrap:hover .bar { opacity: 0.7; }
  .bar-count { font-size: 9px; color: #8c8478; margin-bottom: 4px; min-height: 12px; }
  .bar-label { font-size: 9px; color: #8c8478; margin-top: 4px; letter-spacing: 1px; }
  .chart-caption { font-size: 9px; letter-spacing: 3px; text-transform: uppercase; color: #8c8478; margin-bottom: 32px; }
  td a { color: #1a1714; text-decoration: none; border-bottom: 1px solid #c8c0b0; }
  td a:hover { border-bottom-color: #1a1714; }
  .empty-cell { padding: 32px; text-align: center; color: #8c8478; font-style: italic; }
</style>
</head>
<body>
  <div class="topbar">
    <h1>Battonaasje</h1>
    <nav class="topnav">
      <a href="/logs?secret=${encodeURIComponent(provided)}">Toegangslog</a>
      <a href="/stats?secret=${encodeURIComponent(provided)}" class="active">Bezoekers</a>
      <a href="/voorraad?secret=${encodeURIComponent(provided)}">Voorraad</a>
    </nav>
  </div>
  <div class="sub">Bezoekersstatistieken — bewaard 90 dagen, alleen geverifieerde sessies</div>

  <div class="stats">
    <div class="stat"><div class="stat-label">Vandaag</div><div class="stat-value">${totalToday}</div></div>
    <div class="stat"><div class="stat-label">Deze week</div><div class="stat-value">${totalWeek}</div></div>
    <div class="stat"><div class="stat-label">Totaal (90d)</div><div class="stat-value">${totalAll}</div></div>
  </div>

  <div class="section-title">Laatste 30 dagen</div>
  <div class="chart">${chartBars}</div>
  <div class="chart-caption">Bezoeken per dag</div>

  <div class="section-title">Populaire pagina's</div>
  <table>
    <thead><tr><th>Pagina</th><th style="text-align:right">Bezoeken</th></tr></thead>
    <tbody>${pagesRows}</tbody>
  </table>
</body></html>`;

  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

// ─── Shared CSS for /logs and /stats ─────────────────────────────────────────
const SHARED_CSS = `<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; background: #f2ede4; color: #1a1714; padding: 48px 32px; }
  .topbar { display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap; gap: 16px; margin-bottom: 4px; }
  h1 { font-size: 22px; letter-spacing: 6px; text-transform: uppercase; }
  .topnav { display: flex; gap: 16px; }
  .topnav a { font-size: 10px; letter-spacing: 3px; text-transform: uppercase; color: #8c8478; text-decoration: none; padding-bottom: 4px; border-bottom: 1px solid transparent; }
  .topnav a:hover { color: #1a1714; }
  .topnav a.active { color: #1a1714; border-bottom-color: #1a1714; }
  .sub { font-size: 11px; letter-spacing: 2px; color: #8c8478; margin-bottom: 32px; }
  .section-title { font-size: 10px; letter-spacing: 3px; text-transform: uppercase; color: #8c8478; margin: 32px 0 12px; padding-bottom: 8px; border-bottom: 1px solid #c8c0b0; }
  .stats { display: flex; gap: 24px; margin-bottom: 32px; flex-wrap: wrap; }
  .stat { background: #e8e2d6; padding: 14px 20px; min-width: 120px; }
  .stat-label { font-size: 9px; letter-spacing: 3px; text-transform: uppercase; color: #8c8478; margin-bottom: 6px; }
  .stat-value { font-size: 28px; color: #1a1714; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; font-size: 9px; letter-spacing: 3px; text-transform: uppercase; color: #8c8478; border-bottom: 1px solid #c8c0b0; padding: 10px 12px; }
  td { padding: 10px 12px; border-bottom: 1px solid #e8e2d6; vertical-align: top; }
  tr:hover td { background: #ede8df; }
  .ua { font-size: 11px; color: #666; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .empty { padding: 48px; text-align: center; color: #8c8478; font-style: italic; }
</style>`;

// ─── Main handler ─────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const url    = new URL(request.url);

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // HTML viewers
    if (request.method === 'GET' && url.pathname === '/logs')     return handleLogs(request, env);
    if (request.method === 'GET' && url.pathname === '/stats')    return handleStats(request, env);
    if (request.method === 'GET' && url.pathname === '/voorraad') return handleVoorraadAdmin(request, env);

    // Public stock JSON for frontend
    if (request.method === 'GET' && url.pathname === '/stock')    return handleStockRead(request, env);

    // Voorraad admin update
    if (request.method === 'POST' && url.pathname === '/voorraad') return handleVoorraadAdmin(request, env);

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const ip      = request.headers.get('CF-Connecting-IP') || 'unknown';
    const country = request.headers.get('CF-IPCountry')     || '??';
    const ua      = request.headers.get('User-Agent')       || '';

    // ── POST /track — record pageview ──────────────────────────────────────
    if (url.pathname === '/track') {
      if (isRateLimited(trackAttempts, ip, TRACK_MAX_ATTEMPTS, TRACK_WINDOW_MS)) {
        return new Response('', { status: 429, headers: corsHeaders(origin) });
      }
      let body;
      try { body = await request.json(); } catch {
        return new Response('', { status: 400, headers: corsHeaders(origin) });
      }
      const page = sanitizePath(body.page);
      await recordPageview(env, page);
      return new Response('', { status: 204, headers: corsHeaders(origin) });
    }

    // ── POST /verify — gate authentication ────────────────────────────────
    if (url.pathname === '/verify' || url.pathname === '/') {
      if (isRateLimited(verifyAttempts, ip, VERIFY_MAX_ATTEMPTS, VERIFY_WINDOW_MS)) {
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

      await logAttempt(env, ip, country, ua, valid);

      return new Response(JSON.stringify({ ok: valid }), {
        status: valid ? 200 : 401,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }

    return new Response('Not Found', { status: 404 });
  },
};
