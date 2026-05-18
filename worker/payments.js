// Battonaasje — Mollie payments Worker
// Deploy as a second Worker named "battonaasje-payments"
//
// Required secrets:
//   MOLLIE_API_KEY  — test_xxx during testing, live_xxx in production
//
// Optional KV binding (for storing orders):
//   ORDERS  — every successful payment is stored as JSON, keyed by Mollie payment ID
//
// Endpoints:
//   POST /order            — { slug, qty, email } → { ok, checkoutUrl, id }
//   POST /webhook          — Mollie status callback
//   GET  /status?id=...    — { ok, status, slug, qty, total }
//   GET  /orders?secret=.. — HTML admin viewer of all orders

const ALLOWED_ORIGINS = [
  'https://battonaasje.nl',
  'https://www.battonaasje.nl',
  'http://localhost:3456',
];

// ─── PRICE CATALOG (server-side, tamper-proof) ────────────────────────────────
// Edit these prices to match what you actually charge. Frontend only sends
// the slug; this server adds the price so users can't manipulate it via DevTools.
const CATALOG = {
  'frerejean-freres-champagne': {
    name:  'Frerejean Frères Premier Cru',
    price: 75.00,
    unit:  'fles',
  },
  'chablis-grand-cru-blanchot-1991': {
    name:  'Defaix Chablis Grand Cru Blanchot 1991',
    price: 295.00,
    unit:  'fles',
  },
  'massolino-barolo-2019-magnum': {
    name:  'Massolino Barolo 2019 Magnum',
    price: 180.00,
    unit:  'magnum',
  },
};

const MAX_QTY = 12;

// ─── Helpers ──────────────────────────────────────────────────────────────────
function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age':       '86400',
  };
}

// Security headers — applied to every response (2026 best practices)
const SECURITY_HEADERS = {
  'Strict-Transport-Security':   'max-age=63072000; includeSubDomains; preload',
  'X-Content-Type-Options':      'nosniff',
  'X-Frame-Options':             'DENY',
  'Referrer-Policy':             'strict-origin-when-cross-origin',
  'Permissions-Policy':          'camera=(), microphone=(), geolocation=(), interest-cohort=(), browsing-topics=()',
  'X-Permitted-Cross-Domain-Policies': 'none',
};
function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
  return new Response(response.body, { status: response.status, headers });
}

function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

function isValidEmail(s) {
  return typeof s === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= 200;
}

// ─── Order storage ────────────────────────────────────────────────────────────
async function storeOrder(env, paymentId, data) {
  if (!env.ORDERS) return;
  try {
    await env.ORDERS.put(`order:${paymentId}`, JSON.stringify(data), {
      expirationTtl: 2 * 365 * 24 * 60 * 60, // 2 years (legal retention)
    });
  } catch (err) {
    console.error('storeOrder failed', err);
  }
}

// ─── /orders HTML admin viewer ────────────────────────────────────────────────
async function handleOrdersView(request, env) {
  const provided = new URL(request.url).searchParams.get('secret') || '';
  if (!env.LOG_SECRET || provided !== env.LOG_SECRET) {
    return new Response('Unauthorized', { status: 401 });
  }
  if (!env.ORDERS) {
    return new Response('<h1>ORDERS KV not bound</h1>', { status: 500, headers: { 'Content-Type': 'text/html' } });
  }

  let keys = [];
  try {
    const listed = await env.ORDERS.list({ prefix: 'order:', limit: 1000 });
    keys = listed.keys.slice(-200).reverse();
  } catch {
    return new Response('KV error', { status: 500 });
  }

  const orders = await Promise.all(
    keys.map(async ({ name }) => {
      const raw = await env.ORDERS.get(name);
      try { return raw ? JSON.parse(raw) : null; } catch { return null; }
    })
  );

  const rows = orders.filter(Boolean).map((o) => {
    const date = new Date(o.ts).toLocaleString('nl-NL', { timeZone: 'Europe/Amsterdam' });
    const status = o.status === 'paid'
      ? '<span style="color:#2a7a3b;font-weight:600">✓ Betaald</span>'
      : o.status === 'failed' || o.status === 'canceled' || o.status === 'expired'
        ? `<span style="color:#a05040;font-weight:600">✗ ${o.status}</span>`
        : `<span style="color:#8c8478">${o.status}</span>`;
    return `<tr>
      <td>${date}</td>
      <td>${status}</td>
      <td>${o.email || '-'}</td>
      <td>${o.slug || '-'}</td>
      <td style="text-align:right">${o.qty || 1}</td>
      <td style="text-align:right">€${(o.total || 0).toFixed(2)}</td>
      <td style="font-size:11px;color:#666">${o.id}</td>
    </tr>`;
  }).join('\n');

  const paid       = orders.filter((o) => o?.status === 'paid');
  const revenue    = paid.reduce((s, o) => s + (o.total || 0), 0);
  const html = `<!DOCTYPE html>
<html lang="nl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Battonaasje — Bestellingen</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; background: #f2ede4; color: #1a1714; padding: 48px 32px; }
  h1 { font-size: 22px; letter-spacing: 6px; text-transform: uppercase; margin-bottom: 8px; }
  .sub { font-size: 11px; letter-spacing: 2px; color: #8c8478; margin-bottom: 32px; }
  .stats { display: flex; gap: 24px; margin-bottom: 32px; flex-wrap: wrap; }
  .stat { background: #e8e2d6; padding: 14px 20px; min-width: 120px; }
  .stat-label { font-size: 9px; letter-spacing: 3px; text-transform: uppercase; color: #8c8478; margin-bottom: 6px; }
  .stat-value { font-size: 28px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; font-size: 9px; letter-spacing: 3px; text-transform: uppercase; color: #8c8478; border-bottom: 1px solid #c8c0b0; padding: 10px 12px; }
  td { padding: 10px 12px; border-bottom: 1px solid #e8e2d6; }
  tr:hover td { background: #ede8df; }
</style>
</head><body>
<h1>Battonaasje</h1>
<div class="sub">Bestellingen — laatste ${orders.length} (bewaard 2 jaar)</div>
<div class="stats">
  <div class="stat"><div class="stat-label">Totaal</div><div class="stat-value">${orders.length}</div></div>
  <div class="stat"><div class="stat-label">Betaald</div><div class="stat-value" style="color:#2a7a3b">${paid.length}</div></div>
  <div class="stat"><div class="stat-label">Omzet</div><div class="stat-value">€${revenue.toFixed(2)}</div></div>
</div>
${orders.length === 0 ? '<p style="text-align:center;padding:48px;color:#8c8478;font-style:italic">Nog geen bestellingen.</p>' : `
<table>
  <thead><tr><th>Tijdstip</th><th>Status</th><th>Email</th><th>Wijn</th><th style="text-align:right">Aantal</th><th style="text-align:right">Totaal</th><th>Mollie ID</th></tr></thead>
  <tbody>${rows}</tbody>
</table>`}
</body></html>`;
  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

// ─── Main handler ─────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    return withSecurityHeaders(await handleRequest(request, env));
  },
};

async function handleRequest(request, env) {
    const origin = request.headers.get('Origin') || '';
    const url    = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // ── GET /orders — admin viewer ────────────────────────────────────────
    if (request.method === 'GET' && url.pathname === '/orders') {
      return handleOrdersView(request, env);
    }

    // ── POST /order — create Mollie payment ───────────────────────────────
    if (request.method === 'POST' && url.pathname === '/order') {
      let body;
      try { body = await request.json(); } catch {
        return json({ ok: false, error: 'invalid_body' }, 400, origin);
      }

      const { slug, qty: rawQty, email, redirectUrl } = body;
      const item = CATALOG[slug];

      if (!item)                                       return json({ ok: false, error: 'unknown_wine' }, 400, origin);
      if (!isValidEmail(email))                        return json({ ok: false, error: 'invalid_email' }, 400, origin);
      const qty = parseInt(rawQty, 10);
      if (!qty || qty < 1 || qty > MAX_QTY)            return json({ ok: false, error: 'invalid_qty' }, 400, origin);
      if (!redirectUrl || !redirectUrl.startsWith('https://battonaasje.nl/'))
                                                       return json({ ok: false, error: 'invalid_redirect' }, 400, origin);
      if (!env.MOLLIE_API_KEY)                         return json({ ok: false, error: 'no_api_key' }, 500, origin);

      const total = +(item.price * qty).toFixed(2);

      const mollieRes = await fetch('https://api.mollie.com/v2/payments', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.MOLLIE_API_KEY}`,
          'Content-Type':  'application/json',
        },
        body: JSON.stringify({
          amount:      { currency: 'EUR', value: total.toFixed(2) },
          description: `${item.name} × ${qty}`,
          redirectUrl,
          webhookUrl:  `${url.origin}/webhook`,
          metadata:    { slug, qty, email, name: item.name, total },
        }),
      });

      const payment = await mollieRes.json();
      if (!mollieRes.ok) {
        console.error('Mollie create failed', payment);
        return json({ ok: false, error: payment.detail || 'payment_error' }, 502, origin);
      }

      // Store pending order
      await storeOrder(env, payment.id, {
        id:     payment.id,
        ts:     Date.now(),
        slug,
        name:   item.name,
        qty,
        total,
        email,
        status: payment.status, // 'open' initially
      });

      return json({ ok: true, checkoutUrl: payment._links.checkout.href, id: payment.id }, 200, origin);
    }

    // ── POST /webhook — Mollie status callback ───────────────────────────
    if (request.method === 'POST' && url.pathname === '/webhook') {
      const text = await request.text();
      const id   = new URLSearchParams(text).get('id');
      if (!id) return new Response('', { status: 200 });

      const mollieRes = await fetch(`https://api.mollie.com/v2/payments/${id}`, {
        headers: { 'Authorization': `Bearer ${env.MOLLIE_API_KEY}` },
      });
      if (!mollieRes.ok) return new Response('', { status: 200 });
      const payment = await mollieRes.json();

      // Merge fresh status into stored order
      if (env.ORDERS) {
        const raw = await env.ORDERS.get(`order:${id}`);
        const existing = raw ? JSON.parse(raw) : { id, ts: Date.now() };
        const md = payment.metadata || {};
        await storeOrder(env, id, {
          ...existing,
          slug:   md.slug   || existing.slug,
          name:   md.name   || existing.name,
          qty:    md.qty    || existing.qty,
          total:  md.total  || existing.total,
          email:  md.email  || existing.email,
          status: payment.status,
        });
      }

      console.log(`Mollie ${id} → ${payment.status}`);
      return new Response('', { status: 200 });
    }

    // ── GET /status — frontend polls after Mollie redirect ────────────────
    if (request.method === 'GET' && url.pathname === '/status') {
      const id = url.searchParams.get('id');
      if (!id) return json({ ok: false, error: 'missing_id' }, 400, origin);

      const mollieRes = await fetch(`https://api.mollie.com/v2/payments/${id}`, {
        headers: { 'Authorization': `Bearer ${env.MOLLIE_API_KEY}` },
      });
      if (!mollieRes.ok) return json({ ok: false, error: 'not_found' }, 404, origin);

      const payment = await mollieRes.json();
      const md      = payment.metadata || {};
      return json({
        ok:     true,
        status: payment.status,
        slug:   md.slug,
        name:   md.name,
        qty:    md.qty,
        total:  md.total,
        email:  md.email,
      }, 200, origin);
    }

    return new Response('Not Found', { status: 404 });
}
