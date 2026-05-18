# Cloudflare dashboard security checklist

Items voor jou om in de Cloudflare dashboard aan te zetten (code-changes
zijn al gedaan, maar dit zijn dashboard-instellingen).

---

## 🚨 Stap 0 — Domain proxy CHECK (cruciaal!)

Zonder dit werkt **niks** van Cloudflare's DDoS/WAF/Bot-bescherming op
battonaasje.nl zelf (alleen op de Worker subdomeinen).

1. Cloudflare dashboard → kies **battonaasje.nl** zone
2. **DNS** → check records voor `battonaasje.nl` en `www.battonaasje.nl`
3. Per record moet er een **🟠 oranje wolkje** "Proxied" staan
   - 🟠 Proxied = traffic gaat door Cloudflare = DDoS-bescherming actief
   - ⚫ DNS only = traffic gaat rechtstreeks naar GitHub Pages = geen bescherming

**Als je grijze wolkjes ziet:** klik erop om naar oranje te switchen.

> Als je GitHub Pages gebruikt: Cloudflare Pro/Business plans bieden
> "CNAME flattening" voor apex-domains. Op het free plan moet je
> waarschijnlijk een CNAME `kxrann.github.io` records gebruiken met proxy ON.

---

## 🛡️ Stap 1 — DDoS Protection (gratis, automatisch maar verifiëren)

1. **Security** → **DDoS** (of **Security** → **WAF** → **DDoS rules**)
2. "HTTP DDoS Attack Protection" → moet **Enabled** zijn met sensitivity **High**
3. "Network-layer DDoS Attack Protection" → **Enabled**

> Tip: laat sensitivity op High. Als je ooit false positives ziet (echte
> bezoekers worden geweerd), kun je tijdelijk naar Medium.

---

## 🔥 Stap 2 — WAF Managed Rules (gratis)

1. **Security** → **WAF** → **Managed rules**
2. **Cloudflare Free Managed Ruleset** → **Enabled**
3. Action: laat op standaard (Block) — beschermt tegen CVE's en bekende exploits

---

## 🤖 Stap 3 — Bot Fight Mode (gratis, extra naast Turnstile)

1. **Security** → **Bots**
2. **Bot Fight Mode** → **On**
3. Vangt simpele bots (curl, scrapers) voordat ze de Worker bereiken

---

## 🔒 Stap 4 — SSL/TLS instellingen

1. **SSL/TLS** → **Overview**
2. **Encryption mode**: zet op **Full (strict)**
   (Niet Flexible — dat is onveilig: deel van het pad onversleuteld)
3. **Edge Certificates** → **Always Use HTTPS**: **On**
4. **Edge Certificates** → **HTTP Strict Transport Security (HSTS)**:
   - Max-Age: **6 months** (start hier) → later **12 months** → eventueel **24 months**
   - Include subdomains: **On**
   - Preload: **On** (pas aanzetten als alles werkt — preload is permanent!)
5. **Edge Certificates** → **Minimum TLS Version**: **TLS 1.2** (1.3 als optie)
6. **Edge Certificates** → **TLS 1.3**: **On**

> ⚠️ HSTS preload is praktisch permanent. Test eerst grondig met max-age
> 6 maanden voordat je preload aanzet en submit naar hstspreload.org.

---

## 🚧 Stap 5 — Rate Limiting (gratis tot 10k requests/maand)

Optioneel — wij hebben al rate-limiting in de Worker, maar Cloudflare's
versie zit op de edge (sneller).

1. **Security** → **WAF** → **Rate limiting rules**
2. Maak rule: "Verify spam"
   - If URL path equals `/verify`
   - Same IP, 20 requests per 1 minute
   - Action: **Block** voor 10 minutes

Niet noodzakelijk maar extra laag.

---

## 🌍 Stap 6 — Security level

1. **Security** → **Settings**
2. **Security Level**: **Medium** (standaard) — soms kortstondig "Under Attack"
3. **Browser Integrity Check**: **On**
4. **Privacy Pass Support**: **On** (gratis, helpt echte gebruikers)

---

## 📧 Stap 7 — Email-route voor security.txt

We hebben `/.well-known/security.txt` met `mailto:security@battonaasje.nl`.
Zorg dat dit adres werkt:

1. Optie A: Email forwarder via je domeinregistrar
2. Optie B: Cloudflare Email Routing (gratis):
   - **Email** → **Email Routing**
   - Voeg adres toe: `security@battonaasje.nl` → forward naar je persoonlijke email

---

## ✅ Verificatie

Na bovenstaande, test op:

- https://securityheaders.com/?q=battonaasje.nl → moet **A** of **A+** krijgen
- https://www.ssllabs.com/ssltest/analyze.html?d=battonaasje.nl → moet **A+** krijgen
- https://hstspreload.org/?domain=battonaasje.nl → check requirements

---

## Wat is al code-side gedaan (geen actie nodig)

- ✅ CSP met `default-src 'none'` + `frame-ancestors 'none'` + `upgrade-insecure-requests`
- ✅ HSTS via Worker responses (2 jaar, preload-ready)
- ✅ X-Frame-Options DENY (Workers) / SAMEORIGIN (site)
- ✅ X-Content-Type-Options nosniff
- ✅ Referrer-Policy strict-origin-when-cross-origin
- ✅ Permissions-Policy (opt-out FLoC, Topics)
- ✅ Cross-Origin-Opener-Policy: same-origin
- ✅ Turnstile bot-bescherming op private gate
- ✅ Honeypot trap in private gate
- ✅ Worker rate limits op /verify, /track, /stock, /photos
- ✅ Audit log met IP + country + UA (30d retention)
- ✅ robots.txt + security.txt
- ✅ Server-side Mollie price catalog (no client tampering)
