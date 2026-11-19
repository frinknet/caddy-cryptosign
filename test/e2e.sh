#!/bin/sh
# End-to-end checks against the image ./build.sh produces.
#
#   sh test/e2e.sh
#
# E2E_IMAGE overrides the image (default: the NOTICE slug with a :test tag).
# E2E_PORT overrides the published host port (default: 9099).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

SLUG=$(sed -n '1s/^[^:]*: //p' ./NOTICE)
IMAGE="${E2E_IMAGE:-${SLUG}:test}"
PORT="${E2E_PORT:-9099}"
BASE="http://127.0.0.1:$PORT"
NAME="caddy-cryptosign-e2e"
FIXTURES="$ROOT/test/e2e/fixtures"
TMP=$(mktemp -d /tmp/caddy-cryptosign-e2e-XXXXXX)
PASS=0
FAIL=0

cleanup() {
	docker rm -f "$NAME" >/dev/null 2>&1 || true
	rm -rf "$TMP"
}
trap cleanup EXIT

pass() {
	PASS=$((PASS + 1))
	echo "ok - $1"
}

fail() {
	FAIL=$((FAIL + 1))
	echo "not ok - $1"
}

docker image inspect "$IMAGE" >/dev/null 2>&1 || {
	echo "test/e2e.sh: image $IMAGE not found; build it with ./build.sh" >&2
	exit 1
}

# ── The module is compiled in and registers the right ID ──────────────
if timeout 60 docker run --rm "$IMAGE" list-modules |
	grep -qx 'http.handlers.templates.functions.crypto'; then
	pass "image registers http.handlers.templates.functions.crypto"
else
	fail "image registers http.handlers.templates.functions.crypto"
fi

if timeout 60 docker run --rm "$IMAGE" list-modules |
	grep -qx 'http.handlers.cryptobody'; then
	pass "image registers http.handlers.cryptobody"
else
	fail "image registers http.handlers.cryptobody"
fi

# ── The pinned Caddy version is the one linked into the image ─────────
WANT_CADDY=$(grep -E '(^|[[:space:]])github\.com/caddyserver/caddy/v2[[:space:]]+v' go.mod |
	sed 's/.*github\.com\/caddyserver\/caddy\/v2[[:space:]]*\(v[^[:space:]]*\).*/\1/' | head -1)
if [ -n "$WANT_CADDY" ] &&
	timeout 60 docker run --rm --entrypoint /bin/cat "$IMAGE" /usr/share/licenses/versions.txt |
		grep -q "^[[:space:]]*dep[[:space:]]*github\.com/caddyserver/caddy/v2[[:space:]]*$WANT_CADDY[[:space:]]"; then
	pass "image links Caddy $WANT_CADDY from go.mod"
else
	fail "image links Caddy ${WANT_CADDY:-unknown} from go.mod"
fi

# ── Caddyfile validation ──────────────────────────────────────────────
if timeout 60 docker run --rm \
	-v "$FIXTURES/Caddyfile":/etc/caddy/Caddyfile:ro \
	"$IMAGE" validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
	pass "fixture Caddyfile validates"
else
	fail "fixture Caddyfile validates"
fi

# The image copies www/ to /srv/www but installs no /etc/caddy/Caddyfile, so
# validate the shipped file from the repository through the image's adapter.
if timeout 60 docker run --rm \
	-v "$ROOT/www/Caddyfile":/etc/caddy/Caddyfile:ro \
	"$IMAGE" validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
	pass "shipped Caddyfile validates"
else
	fail "shipped Caddyfile validates"
fi

cat >"$TMP/broken.Caddyfile" <<'CADDY'
:80 {
	templates {
		extensions {
			not_a_real_extension
		}
	}
}
CADDY

if timeout 60 docker run --rm \
	-v "$TMP/broken.Caddyfile":/etc/caddy/Caddyfile:ro \
	"$IMAGE" validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
	fail "unknown template extension is rejected"
else
	pass "unknown template extension is rejected"
fi

# ── Serve the fixture site ───────────────────────────────────────────
timeout 60 docker run -d --name "$NAME" \
	-p "127.0.0.1:$PORT:80" \
	-v "$FIXTURES/Caddyfile":/etc/caddy/Caddyfile:ro \
	-v "$FIXTURES/www":/srv/e2e:ro \
	"$IMAGE" run --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null

ready=0
i=0
while [ "$i" -lt 40 ]; do
	if timeout 5 curl -fsS "$BASE/index.html" >/dev/null 2>&1; then
		ready=1
		break
	fi
	i=$((i + 1))
	sleep 0.25
done

if [ "$ready" -eq 1 ]; then
	pass "fixture site is serving"
else
	fail "fixture site is serving"
	timeout 30 docker logs "$NAME" 2>&1 | tail -20 >&2
fi

# ── Exact-byte checks ────────────────────────────────────────────────
if [ "$ready" -eq 1 ]; then
	if timeout 10 curl -fsS "$BASE/index.html" -o "$TMP/index.got" &&
		cmp -s "$TMP/index.got" "$FIXTURES/expected/index.txt"; then
		pass "token, hmac, stripe, skew, soft, and policy output matches exactly"
	else
		fail "token, hmac, stripe, skew, soft, and policy output matches exactly"
		diff -u "$FIXTURES/expected/index.txt" "$TMP/index.got" >&2 || true
	fi

	# The raw request body is captured byte-for-byte before templates render;
	# the page signs and verifies the captured bytes and echoes them back.
	if printf '%s' '{"b":2, "a":1}' |
		timeout 10 curl -fsS -X POST --data-binary @- "$BASE/webhook.html" -o "$TMP/webhook.got" &&
		cmp -s "$TMP/webhook.got" "$FIXTURES/expected/webhook.txt"; then
		pass "raw webhook body is captured and verified exactly"
	else
		fail "raw webhook body is captured and verified exactly"
		diff -u "$FIXTURES/expected/webhook.txt" "$TMP/webhook.got" >&2 || true
	fi

	for page in expired tampered nosecret wrongsecret nbf badttl malformed nonobject missingkid audmismatch; do
		code=$(timeout 10 curl -sS -o "$TMP/$page.got" -w '%{http_code}' "$BASE/$page.html") || code=000
		if [ "$code" = 500 ] && cmp -s "$TMP/$page.got" "$FIXTURES/expected/error.txt"; then
			pass "$page page fails closed with 500"
		else
			fail "$page page fails closed with 500 (status $code)"
			cat "$TMP/$page.got" >&2 2>/dev/null || true
		fi
	done
fi

echo
echo "e2e: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
