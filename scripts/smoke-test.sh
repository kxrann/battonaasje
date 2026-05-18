#!/usr/bin/env bash
# Battonaasje — smoke test for the Cloudflare Workers.
# Run after any Worker deploy to catch silently broken endpoints.
#
# Usage:
#   LOG_SECRET=xxx ./scripts/smoke-test.sh
#
# Or:
#   ./scripts/smoke-test.sh xxx

set -u

SECRET="${LOG_SECRET:-${1:-}}"
if [ -z "$SECRET" ]; then
  echo "Usage: LOG_SECRET=xxx $0   (or pass as 1st arg)"
  exit 1
fi

GATE="https://battonaasje-gate.kyranboi123.workers.dev"
PAY="https://battonaasje-payments.kyranboi123.workers.dev"
PASS=0; FAIL=0; SKIP=0

check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    echo "  ✓ $name → $actual"
    PASS=$((PASS+1))
  else
    echo "  ✗ $name → expected $expected, got $actual"
    FAIL=$((FAIL+1))
  fi
}

status() {
  curl -s -o /dev/null -w '%{http_code}' "$@"
}

echo
echo "── GATE WORKER ($GATE) ─────────────────────────────────────────"

# Admin viewers
check "/logs?secret=…"     200 "$(status "$GATE/logs?secret=$SECRET")"
check "/logs (no secret)"  401 "$(status "$GATE/logs")"
check "/stats?secret=…"    200 "$(status "$GATE/stats?secret=$SECRET")"
check "/voorraad?secret=…" 200 "$(status "$GATE/voorraad?secret=$SECRET")"
check "/foto-upload?secret=…" 200 "$(status "$GATE/foto-upload?secret=$SECRET")"

# Public JSON
check "/stock"   200 "$(status "$GATE/stock")"
check "/photos?slug=frerejean-freres-champagne" 200 \
  "$(status "$GATE/photos?slug=frerejean-freres-champagne")"
check "/photos?slug=invalid!"  400 "$(status "$GATE/photos?slug=invalid%21")"

# /verify behavior
check "/verify bad code → 401" 401 \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATE/verify" \
     -H 'Content-Type: application/json' -d '{"code":"NOPE"}' \
     -H "Origin: https://battonaasje.nl")"

check "/verify empty body → 400" 400 \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATE/verify" \
     -H 'Content-Type: application/json' \
     -H "Origin: https://battonaasje.nl")"

# /track
check "/track valid → 204" 204 \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATE/track" \
     -H 'Content-Type: application/json' -d '{"page":"/smoke-test"}' \
     -H "Origin: https://battonaasje.nl")"

# Unknown
check "/nope → 404"        404 "$(status "$GATE/nope")"

echo
echo "── PAYMENTS WORKER ($PAY) ──────────────────────────────────────"

PAY_STATUS=$(status "$PAY/orders?secret=$SECRET")
if [ "$PAY_STATUS" = "000" ] || [ "$PAY_STATUS" = "404" ]; then
  echo "  ⚠️  payments Worker not deployed (skipping)"
  SKIP=$((SKIP+1))
else
  check "/orders?secret=…"  200 "$PAY_STATUS"
  check "/orders no secret" 401 "$(status "$PAY/orders")"
  check "/status missing id" 400 "$(status "$PAY/status")"
fi

echo
echo "── SUMMARY ─────────────────────────────────────────────────────"
echo "  $PASS passed · $FAIL failed · $SKIP skipped"
[ $FAIL -eq 0 ]
