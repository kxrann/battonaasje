// Battonaasje — payment Worker
// Deploy as a second Worker named battonaasje-payments
// Secrets to set via: wrangler secret put MOLLIE_API_KEY
//
// Endpoints:
//   POST /order   — create a Mollie payment, returns { ok, checkoutUrl, id }
//   POST /webhook — Mollie calls this when payment status changes
//   GET  /status  — ?id=xxx, returns { ok, status }
//
// CSP note: if you add embedded Mollie components (card fields) to your pages,
// add https://js.mollie.com to script-src and frame-src. For redirect checkout
// (current setup) no extra CSP is needed — users are redirected to Mollie's
// own domain and back.

const ALLOWED_ORIGINS = [
  'https://battonaasje.nl',
  'https://www.battonaasje.nl',
  'http://localhost:3456',
];

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // POST /order — create a Mollie payment
    if (request.method === 'POST' && url.pathname === '/order') {
      let body;
      try { body = await request.json(); } catch {
        return json({ ok: false, error: 'invalid_body' }, 400, origin);
      }

      const { items, email, redirectUrl } = body;
      if (!items?.length || !email || !redirectUrl) {
        return json({ ok: false, error: 'missing_fields' }, 400, origin);
      }

      // Calculate total from items array: [{ name, price, qty }]
      const total = items.reduce((sum, item) => sum + item.price * item.qty, 0);

      const mollieRes = await fetch('https://api.mollie.com/v2/payments', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.MOLLIE_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          amount: { currency: 'EUR', value: total.toFixed(2) },
          description: 'Battonaasje bestelling',
          redirectUrl,
          webhookUrl: `${url.origin}/webhook`,
          metadata: { email, items },
        }),
      });

      const payment = await mollieRes.json();
      if (!mollieRes.ok) {
        return json({ ok: false, error: payment.detail || 'payment_error' }, 502, origin);
      }

      return json({ ok: true, checkoutUrl: payment._links.checkout.href, id: payment.id }, 200, origin);
    }

    // POST /webhook — Mollie sends payment status updates here
    if (request.method === 'POST' && url.pathname === '/webhook') {
      const body = await request.text();
      const id = new URLSearchParams(body).get('id');
      if (!id) return new Response('', { status: 200 });

      const mollieRes = await fetch(`https://api.mollie.com/v2/payments/${id}`, {
        headers: { 'Authorization': `Bearer ${env.MOLLIE_API_KEY}` },
      });
      const payment = await mollieRes.json();

      // TODO: on payment.status === 'paid':
      //   - Store order in Cloudflare KV or D1
      //   - Send confirmation email via your email provider
      //   - Notify yourself via WhatsApp or webhook
      console.log(`Payment ${id} status: ${payment.status}`);

      return new Response('', { status: 200 });
    }

    // GET /status?id=... — frontend polls this after redirect back
    if (request.method === 'GET' && url.pathname === '/status') {
      const id = url.searchParams.get('id');
      if (!id) return json({ ok: false, error: 'missing_id' }, 400, origin);

      const mollieRes = await fetch(`https://api.mollie.com/v2/payments/${id}`, {
        headers: { 'Authorization': `Bearer ${env.MOLLIE_API_KEY}` },
      });
      if (!mollieRes.ok) return json({ ok: false, error: 'not_found' }, 404, origin);

      const payment = await mollieRes.json();
      return json({ ok: true, status: payment.status }, 200, origin);
    }

    return new Response('Not Found', { status: 404 });
  },
};
