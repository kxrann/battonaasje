# Security policy

Battonaasje takes security seriously. If you discover a vulnerability,
please report it responsibly by emailing **security@battonaasje.nl**.

We will acknowledge receipt within 48 hours and aim to resolve verified
issues within 14 days.

## Security posture

### Transport
- HTTPS-only (GitHub Pages enforces TLS for the custom domain)
- HSTS (`max-age=31536000; includeSubDomains; preload`) on Worker responses
- `upgrade-insecure-requests` directive on all pages

### Browser hardening (per page)
- Strict Content Security Policy (`default-src 'none'` baseline)
- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` denies camera, microphone, geolocation, FLoC
- `Cross-Origin-Opener-Policy: same-origin`
- Subresource hosted from same origin where possible

### Application
- Private gate with rate-limited verification (10/min/IP)
- Cloudflare Turnstile bot protection
- Hidden honeypot input as secondary bot trap
- KV-backed audit log of every access attempt (IP + country + UA, 30 days)
- Age verification gate (18+ for alcohol)
- All admin endpoints require `LOG_SECRET`
- Photo uploads sanitized (slug pattern, slot whitelist, max 8 MB)
- Server-side price catalog (clients cannot manipulate Mollie amounts)

### Infrastructure
- Cloudflare Workers (rate limits, DDoS auto-mitigation)
- Cloudflare R2 (private writes, public reads via dedicated subdomain)
- Cloudflare KV (90-day retention on analytics, 30-day on logs)
- No third-party trackers or analytics
- No cookies beyond functional consent

### Disclosure
See [/.well-known/security.txt](https://battonaasje.nl/.well-known/security.txt)
for the machine-readable disclosure policy (RFC 9116).

## Out of scope
- Social-engineering or physical attacks
- Denial of service via volumetric traffic (Cloudflare handles)
- Issues in third-party services (Mollie, Cloudflare itself)
- Vulnerabilities requiring physical access to the device
