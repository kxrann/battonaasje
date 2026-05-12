// Battonaasje — private gate verification Worker
// Deploy to Cloudflare Workers, set GATE_CODE as an encrypted secret (not a plain variable)
// wrangler secret put GATE_CODE

const ALLOWED_ORIGINS = [
  'https://battonaasje.nl',
  'https://www.battonaasje.nl',
  'http://localhost:3456',
];

// In-memory rate limit store: ip -> { count, resetAt }
// Resets per isolate restart (good enough for brute-force protection)
const attempts = new Map();
const WINDOW_MS = 60_000; // 1 minute
const MAX_ATTEMPTS = 10;  // per IP per window

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

function isRateLimited(ip) {
  const now = Date.now();
  const entry = attempts.get(ip);
  if (!entry || now > entry.resetAt) {
    attempts.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return false;
  }
  entry.count++;
  return entry.count > MAX_ATTEMPTS;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (isRateLimited(ip)) {
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
    const valid = code.length > 0 && code === gateCode;

    return new Response(JSON.stringify({ ok: valid }), {
      status: valid ? 200 : 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  },
};
