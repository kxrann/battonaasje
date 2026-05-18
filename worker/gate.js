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
const readAttempts   = new Map();
const VERIFY_WINDOW_MS    = 60_000;
const VERIFY_MAX_ATTEMPTS = 10;
const TRACK_WINDOW_MS     = 60_000;
const TRACK_MAX_ATTEMPTS  = 60;   // 1 per second average — generous
const READ_WINDOW_MS      = 60_000;
const READ_MAX_ATTEMPTS   = 120;  // 2 per second — protects R2 from spam

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

// ─── R2: photo management ────────────────────────────────────────────────────
// R2 keys:   wines/<slug>/<slot>.jpg
//            slot ∈ { main, gallery-1, gallery-2, gallery-3, gallery-4 }
// Binding:   PHOTOS (R2 bucket binding)
// Env:       R2_PUBLIC_URL — e.g. "https://pub-xxxxxxxx.r2.dev"

const PHOTO_SLOTS = ['main', 'gallery-1', 'gallery-2', 'gallery-3', 'gallery-4'];
const MAX_UPLOAD_BYTES = 8 * 1024 * 1024; // 8 MB after client-side compression

function isValidSlot(s) {
  return typeof s === 'string' && PHOTO_SLOTS.includes(s);
}

function photoUrl(env, slug, slot) {
  if (!env.R2_PUBLIC_URL) return null;
  return `${env.R2_PUBLIC_URL}/wines/${slug}/${slot}.jpg`;
}

async function getPhotosForSlug(env, slug) {
  if (!env.PHOTOS || !env.R2_PUBLIC_URL) {
    return { main: null, gallery: [null, null, null, null] };
  }
  const listed = await env.PHOTOS.list({ prefix: `wines/${slug}/` });
  const out = { main: null, gallery: [null, null, null, null] };
  for (const obj of listed.objects) {
    const fname = obj.key.split('/').pop().replace('.jpg', '');
    if (fname === 'main') {
      out.main = `${env.R2_PUBLIC_URL}/${obj.key}?v=${obj.uploaded.getTime()}`;
    } else if (fname.startsWith('gallery-')) {
      const i = parseInt(fname.split('-')[1], 10) - 1;
      if (i >= 0 && i < 4) out.gallery[i] = `${env.R2_PUBLIC_URL}/${obj.key}?v=${obj.uploaded.getTime()}`;
    }
  }
  return out;
}

async function getAllPhotos(env) {
  const result = {};
  for (const w of KNOWN_WINES) {
    result[w.slug] = await getPhotosForSlug(env, w.slug);
  }
  return result;
}

// ── GET /photos?slug=... or /photos?all=1 (admin only) ──────────────────────
async function handlePhotosRead(request, env) {
  const origin = request.headers.get('Origin') || '';
  const url    = new URL(request.url);
  const ip     = request.headers.get('CF-Connecting-IP') || 'unknown';

  // Skip rate limit for admin "all" mode — it requires LOG_SECRET anyway
  if (url.searchParams.get('all') !== '1') {
    if (isRateLimited(readAttempts, ip, READ_MAX_ATTEMPTS, READ_WINDOW_MS)) {
      return new Response(JSON.stringify({ ok: false, error: 'rate_limited' }), {
        status: 429, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    }
  }

  if (url.searchParams.get('all') === '1') {
    const provided = url.searchParams.get('secret') || '';
    if (!env.LOG_SECRET || provided !== env.LOG_SECRET) {
      return new Response('Unauthorized', { status: 401 });
    }
    const photos = await getAllPhotos(env);
    return new Response(JSON.stringify({ ok: true, photos }), {
      status: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  }

  const slug = url.searchParams.get('slug') || '';
  if (!SLUG_RE.test(slug)) {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_slug' }), {
      status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }
  const photos = await getPhotosForSlug(env, slug);
  return new Response(JSON.stringify({ ok: true, photos }), {
    status: 200,
    headers: {
      'Content-Type':  'application/json',
      'Cache-Control': 'public, max-age=60',
      ...corsHeaders(origin),
    },
  });
}

// ── POST /photo/upload?secret=... multipart: slug, slot, file ────────────────
async function handlePhotoUpload(request, env) {
  const provided = new URL(request.url).searchParams.get('secret') || '';
  if (!env.LOG_SECRET || provided !== env.LOG_SECRET) return new Response('Unauthorized', { status: 401 });
  if (!env.PHOTOS)                                    return new Response(JSON.stringify({ ok: false, error: 'no_r2' }), { status: 500, headers: { 'Content-Type': 'application/json' } });

  let form;
  try { form = await request.formData(); } catch {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_form' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  const slug = String(form.get('slug') || '');
  const slot = String(form.get('slot') || '');
  const file = form.get('file');

  if (!SLUG_RE.test(slug))           return new Response(JSON.stringify({ ok: false, error: 'invalid_slug' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  if (!isValidSlot(slot))            return new Response(JSON.stringify({ ok: false, error: 'invalid_slot' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  if (!file || typeof file === 'string') return new Response(JSON.stringify({ ok: false, error: 'no_file' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  if (file.size > MAX_UPLOAD_BYTES)  return new Response(JSON.stringify({ ok: false, error: 'too_large' }), { status: 413, headers: { 'Content-Type': 'application/json' } });

  const key = `wines/${slug}/${slot}.jpg`;
  try {
    await env.PHOTOS.put(key, file.stream(), {
      httpMetadata: { contentType: 'image/jpeg', cacheControl: 'public, max-age=31536000' },
    });
  } catch (err) {
    console.error('R2 put failed', err);
    return new Response(JSON.stringify({ ok: false, error: 'r2_failed' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
  return new Response(JSON.stringify({ ok: true, url: photoUrl(env, slug, slot) + '?t=' + Date.now() }), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  });
}

// ── GET /photo-source?secret=...&slug=...&slot=... ──────────────────────────
// Streams an R2 photo back with permissive CORS so the admin can draw it on
// a canvas for client-side rotation. Admin-only.
async function handlePhotoSource(request, env) {
  const url      = new URL(request.url);
  const provided = url.searchParams.get('secret') || '';
  if (!env.LOG_SECRET || provided !== env.LOG_SECRET) return new Response('Unauthorized', { status: 401 });
  if (!env.PHOTOS) return new Response('No R2', { status: 500 });

  const slug = url.searchParams.get('slug') || '';
  const slot = url.searchParams.get('slot') || '';
  if (!SLUG_RE.test(slug) || !isValidSlot(slot)) return new Response('Bad request', { status: 400 });

  const obj = await env.PHOTOS.get(`wines/${slug}/${slot}.jpg`);
  if (!obj) return new Response('Not Found', { status: 404 });

  return new Response(obj.body, {
    status: 200,
    headers: {
      'Content-Type':                'image/jpeg',
      'Cache-Control':               'no-store',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

// ── POST /photo/delete?secret=... body: { slug, slot } ───────────────────────
async function handlePhotoDelete(request, env) {
  const provided = new URL(request.url).searchParams.get('secret') || '';
  if (!env.LOG_SECRET || provided !== env.LOG_SECRET) return new Response('Unauthorized', { status: 401 });
  if (!env.PHOTOS) return new Response(JSON.stringify({ ok: false, error: 'no_r2' }), { status: 500, headers: { 'Content-Type': 'application/json' } });

  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ ok: false, error: 'invalid_body' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  const slug = String(body.slug || '');
  const slot = String(body.slot || '');
  if (!SLUG_RE.test(slug))   return new Response(JSON.stringify({ ok: false, error: 'invalid_slug' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  if (!isValidSlot(slot))    return new Response(JSON.stringify({ ok: false, error: 'invalid_slot' }), { status: 400, headers: { 'Content-Type': 'application/json' } });

  try {
    await env.PHOTOS.delete(`wines/${slug}/${slot}.jpg`);
  } catch (err) {
    console.error('R2 delete failed', err);
  }
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json' } });
}

// ── GET /foto-upload?secret=... — admin HTML ─────────────────────────────────
async function handleFotoAdmin(request, env) {
  const provided = new URL(request.url).searchParams.get('secret') || '';
  if (!env.LOG_SECRET || provided !== env.LOG_SECRET) return new Response('Unauthorized', { status: 401 });

  const allPhotos = await getAllPhotos(env);
  const r2ok      = !!env.PHOTOS && !!env.R2_PUBLIC_URL;

  const wineCards = KNOWN_WINES.map((w) => {
    const photos = allPhotos[w.slug] || { main: null, gallery: [null, null, null, null] };
    const slots = [
      { key: 'main',      label: 'Hoofdfoto (fles)', url: photos.main, aspect: '3/4' },
      { key: 'gallery-1', label: 'Gallery 1',        url: photos.gallery[0], aspect: '4/3' },
      { key: 'gallery-2', label: 'Gallery 2',        url: photos.gallery[1], aspect: '4/3' },
      { key: 'gallery-3', label: 'Gallery 3',        url: photos.gallery[2], aspect: '4/3' },
      { key: 'gallery-4', label: 'Gallery 4',        url: photos.gallery[3], aspect: '4/3' },
    ];
    const slotsHtml = slots.map((s) => `
      <div class="slot" data-slug="${w.slug}" data-slot="${s.key}" style="--ar:${s.aspect}">
        <div class="slot-label">${s.label}</div>
        <div class="slot-tile">
          ${s.url
            ? `<img src="${s.url}" alt="${s.label}" loading="lazy">
               <button type="button" class="slot-rot" title="Roteer 90° met de klok mee" onclick="rotatePhoto('${w.slug}','${s.key}')">↻</button>
               <button type="button" class="slot-del" title="Verwijderen" onclick="deletePhoto('${w.slug}','${s.key}')">×</button>`
            : `<div class="slot-empty"><span>+</span></div>`}
        </div>
        <input type="file" accept="image/*" onchange="uploadPhoto(this, '${w.slug}', '${s.key}')" hidden>
        <button type="button" class="slot-upload" onclick="this.parentNode.querySelector('input[type=file]').click()">${s.url ? 'Vervangen' : 'Upload'}</button>
      </div>`).join('');

    return `<section class="wine-card">
      <h2 class="wine-card-title">${w.name}</h2>
      <div class="wine-card-slug">${w.slug}</div>
      <div class="slot-grid">${slotsHtml}</div>
    </section>`;
  }).join('\n');

  const html = `<!DOCTYPE html>
<html lang="nl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Battonaasje — Foto's</title>
${SHARED_CSS}
<style>
  .warn { background: #fff4e0; border-left: 3px solid #c68b2c; padding: 14px 18px; margin-bottom: 24px; font-size: 12px; color: #6b4f1a; line-height: 1.6; }
  .wine-card { background: #fff; padding: 28px 24px; margin-bottom: 20px; border: 1px solid #c8c0b0; }
  .wine-card-title { font-family: 'Cormorant Garamond', serif; font-weight: 300; font-size: 22px; letter-spacing: 4px; text-transform: uppercase; margin-bottom: 4px; }
  .wine-card-slug { font-size: 11px; color: #8c8478; margin-bottom: 20px; letter-spacing: 1px; }
  .slot-grid { display: grid; grid-template-columns: 1.2fr repeat(4, 1fr); gap: 14px; }
  .slot { display: flex; flex-direction: column; gap: 8px; }
  .slot-label { font-size: 9px; letter-spacing: 2px; text-transform: uppercase; color: #8c8478; }
  .slot-tile { position: relative; background: #ede8df; border: 1px solid #c8c0b0; aspect-ratio: var(--ar, 4/3); overflow: hidden; }
  .slot-tile img { width: 100%; height: 100%; object-fit: cover; display: block; }
  .slot-empty { width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; color: #c8c0b0; font-size: 36px; font-weight: 300; }
  .slot-del { position: absolute; top: 6px; right: 6px; width: 26px; height: 26px; border-radius: 50%; background: rgba(0,0,0,0.7); color: #fff; border: none; cursor: pointer; font-size: 18px; line-height: 1; padding: 0; opacity: 0; transition: opacity 0.15s; }
  .slot-rot { position: absolute; top: 6px; left: 6px; width: 26px; height: 26px; border-radius: 50%; background: rgba(0,0,0,0.7); color: #fff; border: none; cursor: pointer; font-size: 16px; line-height: 1; padding: 0; opacity: 0; transition: opacity 0.15s; display: flex; align-items: center; justify-content: center; }
  .slot-tile:hover .slot-del, .slot-tile:hover .slot-rot { opacity: 1; }
  .slot-upload { padding: 6px 10px; background: #1a1714; color: #f2ede4; border: none; font-family: 'Courier Prime', monospace; font-size: 9px; letter-spacing: 2px; text-transform: uppercase; cursor: pointer; transition: opacity 0.2s; }
  .slot-upload:hover { opacity: 0.85; }
  .slot-tile.uploading { opacity: 0.4; pointer-events: none; }
  .slot-tile.uploading::after { content: '· · ·'; position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-size: 24px; color: #1a1714; letter-spacing: 4px; }
  .toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%); background: #1a1714; color: #f2ede4; padding: 12px 24px; font-size: 12px; letter-spacing: 2px; text-transform: uppercase; opacity: 0; transition: opacity 0.25s; pointer-events: none; z-index: 1000; }
  .toast.visible { opacity: 1; }
  .toast.err { background: #a05040; }
  @media (max-width: 768px) {
    .slot-grid { grid-template-columns: 1fr 1fr; }
    .slot:first-child { grid-column: 1 / -1; }
  }
</style>
</head><body>
<div class="topbar">
  <h1>Battonaasje</h1>
  <nav class="topnav">
    <a href="/logs?secret=${encodeURIComponent(provided)}">Toegangslog</a>
    <a href="/stats?secret=${encodeURIComponent(provided)}">Bezoekers</a>
    <a href="/voorraad?secret=${encodeURIComponent(provided)}">Voorraad</a>
    <a href="/foto-upload?secret=${encodeURIComponent(provided)}" class="active">Foto's</a>
  </nav>
</div>
<div class="sub">Foto-beheer · uploads worden automatisch verkleind tot 1600px JPEG · onmiddellijk zichtbaar op battonaasje.nl</div>

${r2ok ? '' : '<div class="warn"><strong>R2 niet geconfigureerd.</strong> Voeg de PHOTOS bucket-binding en R2_PUBLIC_URL env var toe in de Worker Settings. Tot die tijd kun je geen fotos uploaden.</div>'}

${wineCards}

<div class="toast" id="toast"></div>

<script>
var SECRET = ${JSON.stringify(provided)};

function showToast(msg, err) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.toggle('err', !!err);
  t.classList.add('visible');
  setTimeout(function() { t.classList.remove('visible'); }, 2400);
}

async function resizeImage(file, maxWidth, quality) {
  return new Promise(function(resolve, reject) {
    var url = URL.createObjectURL(file);
    var img = new Image();
    img.onload = function() {
      var scale = Math.min(1, maxWidth / img.width);
      var w = Math.round(img.width * scale);
      var h = Math.round(img.height * scale);
      var canvas = document.createElement('canvas');
      canvas.width = w; canvas.height = h;
      canvas.getContext('2d').drawImage(img, 0, 0, w, h);
      URL.revokeObjectURL(url);
      canvas.toBlob(function(blob) {
        if (!blob) return reject(new Error('canvas_failed'));
        resolve(blob);
      }, 'image/jpeg', quality);
    };
    img.onerror = function() { URL.revokeObjectURL(url); reject(new Error('image_load_failed')); };
    img.src = url;
  });
}

async function uploadPhoto(input, slug, slot) {
  var file = input.files[0];
  if (!file) return;
  var tile = input.parentNode.querySelector('.slot-tile');
  if (tile) tile.classList.add('uploading');
  try {
    var blob = await resizeImage(file, 1600, 0.85);
    var form = new FormData();
    form.append('slug', slug);
    form.append('slot', slot);
    form.append('file', blob, slot + '.jpg');
    var res = await fetch('/photo/upload?secret=' + encodeURIComponent(SECRET), {
      method: 'POST', body: form
    });
    var data = await res.json();
    if (!data.ok) throw new Error(data.error || 'upload_failed');
    showToast('Foto opgeslagen');
    setTimeout(function() { location.reload(); }, 400);
  } catch (err) {
    if (tile) tile.classList.remove('uploading');
    showToast('Fout: ' + err.message, true);
  }
  input.value = '';
}

async function rotatePhoto(slug, slot) {
  var slotEl = document.querySelector('[data-slug="' + slug + '"][data-slot="' + slot + '"]');
  var tile = slotEl ? slotEl.querySelector('.slot-tile') : null;
  if (tile) tile.classList.add('uploading');
  try {
    // Fetch original from R2 via worker proxy (has CORS so canvas can read it)
    var srcRes = await fetch('/photo-source?secret=' + encodeURIComponent(SECRET) +
                             '&slug=' + encodeURIComponent(slug) +
                             '&slot=' + encodeURIComponent(slot));
    if (!srcRes.ok) throw new Error('bron_niet_gevonden');
    var blob = await srcRes.blob();

    // Decode image
    var imgUrl = URL.createObjectURL(blob);
    var img = new Image();
    await new Promise(function(resolve, reject) {
      img.onload = resolve;
      img.onerror = function() { reject(new Error('decode_failed')); };
      img.src = imgUrl;
    });

    // Rotate 90° clockwise on a canvas (swap w/h)
    var canvas = document.createElement('canvas');
    canvas.width  = img.naturalHeight;
    canvas.height = img.naturalWidth;
    var ctx = canvas.getContext('2d');
    ctx.translate(canvas.width / 2, canvas.height / 2);
    ctx.rotate(Math.PI / 2);
    ctx.drawImage(img, -img.naturalWidth / 2, -img.naturalHeight / 2);
    URL.revokeObjectURL(imgUrl);

    // Encode back to JPEG
    var rotated = await new Promise(function(resolve, reject) {
      canvas.toBlob(function(b) { b ? resolve(b) : reject(new Error('encode_failed')); }, 'image/jpeg', 0.9);
    });

    // Upload as same slot — overwrites
    var form = new FormData();
    form.append('slug', slug);
    form.append('slot', slot);
    form.append('file', rotated, slot + '.jpg');
    var res = await fetch('/photo/upload?secret=' + encodeURIComponent(SECRET), {
      method: 'POST', body: form
    });
    var data = await res.json();
    if (!data.ok) throw new Error(data.error || 'upload_failed');
    showToast('Geroteerd');
    setTimeout(function() { location.reload(); }, 400);
  } catch (err) {
    if (tile) tile.classList.remove('uploading');
    showToast('Fout: ' + err.message, true);
  }
}

async function deletePhoto(slug, slot) {
  if (!confirm('Foto verwijderen?')) return;
  try {
    var res = await fetch('/photo/delete?secret=' + encodeURIComponent(SECRET), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slug: slug, slot: slot })
    });
    var data = await res.json();
    if (!data.ok) throw new Error(data.error || 'delete_failed');
    showToast('Foto verwijderd');
    setTimeout(function() { location.reload(); }, 400);
  } catch (err) {
    showToast('Fout: ' + err.message, true);
  }
}
</script>
</body></html>`;
  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
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
  const ip     = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (isRateLimited(readAttempts, ip, READ_MAX_ATTEMPTS, READ_WINDOW_MS)) {
    return new Response(JSON.stringify({ ok: false, error: 'rate_limited' }), {
      status: 429, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    });
  }
  const stock = await getStockMap(env);
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
    <a href="/foto-upload?secret=${encodeURIComponent(provided)}">Foto's</a>
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
      <a href="/foto-upload?secret=${encodeURIComponent(provided)}">Foto's</a>
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
      <a href="/foto-upload?secret=${encodeURIComponent(provided)}">Foto's</a>
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
    if (request.method === 'GET' && url.pathname === '/logs')         return handleLogs(request, env);
    if (request.method === 'GET' && url.pathname === '/stats')        return handleStats(request, env);
    if (request.method === 'GET' && url.pathname === '/voorraad')     return handleVoorraadAdmin(request, env);
    if (request.method === 'GET' && url.pathname === '/foto-upload')  return handleFotoAdmin(request, env);

    // Public JSON
    if (request.method === 'GET' && url.pathname === '/stock')    return handleStockRead(request, env);
    if (request.method === 'GET' && url.pathname === '/photos')   return handlePhotosRead(request, env);

    // Admin POST endpoints
    if (request.method === 'POST' && url.pathname === '/voorraad')      return handleVoorraadAdmin(request, env);
    if (request.method === 'GET'  && url.pathname === '/photo-source')  return handlePhotoSource(request, env);
    if (request.method === 'POST' && url.pathname === '/photo/upload')  return handlePhotoUpload(request, env);
    if (request.method === 'POST' && url.pathname === '/photo/delete')  return handlePhotoDelete(request, env);

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

      let code, tsToken;
      try {
        const body = await request.json();
        code    = (body.code || '').trim().toUpperCase();
        tsToken = body.cfTurnstileToken || null;
      } catch {
        return new Response(JSON.stringify({ ok: false }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
        });
      }

      // Turnstile validation (only enforced if TURNSTILE_SECRET is configured)
      if (env.TURNSTILE_SECRET) {
        if (!tsToken) {
          await logAttempt(env, ip, country, ua, false);
          return new Response(JSON.stringify({ ok: false, error: 'turnstile_missing' }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
          });
        }
        const tsForm = new URLSearchParams();
        tsForm.append('secret',   env.TURNSTILE_SECRET);
        tsForm.append('response', tsToken);
        tsForm.append('remoteip', ip);
        let tsOk = false;
        try {
          const tsRes  = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: tsForm,
          });
          const tsData = await tsRes.json();
          tsOk = !!tsData.success;
        } catch (err) {
          console.error('Turnstile verify failed', err);
        }
        if (!tsOk) {
          await logAttempt(env, ip, country, ua, false);
          return new Response(JSON.stringify({ ok: false, error: 'turnstile_failed' }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
          });
        }
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
