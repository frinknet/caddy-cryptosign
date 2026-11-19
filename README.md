# caddy-cryptosign

Stateless cryptographic primitives for [Caddy](https://caddyserver.com)
templates: mint EdDSA JWTs, sign exact strings with HMAC-SHA256, and verify
either kind. Secrets are passed at call time by the template or application,
so key scoping and rotation stay under caller control rather than living in a
server-global seed.

```caddyfile
example.com {
	root * /var/www
	templates {
		extensions {
			crypto
		}
	}
	file_server
}
```

```html
{{ $token := dict "sub" "user-42" "role" "admin" | toJson | cryptotoken "app-secret" "v1" "15m" }}
{{ $claims := cryptocheck $token "app-secret" }}
signed in as {{ $claims.sub }}
```

Caddy module ID: `http.handlers.templates.functions.crypto` (the `crypto`
extension of the `templates` handler). Source:
`github.com/frinknet/caddy-cryptosign`.

## Contents

- [Installation](#installation)
- [Enabling the functions](#enabling-the-functions)
- [cryptotoken](#cryptotoken)
- [cryptosign](#cryptosign)
- [cryptocheck](#cryptocheck)
- [Key derivation](#key-derivation)
- [Security properties](#security-properties)
- [Examples](#examples)
- [Build and test](#build-and-test)
- [Image](#image)
- [Layout](#layout)
- [Limitations](#limitations)
- [License](#license)

## Installation

Build a Caddy binary with the plugin:

```sh
xcaddy build --with github.com/frinknet/caddy-cryptosign
```

Or build the container image this repository ships:

```sh
./build.sh
```

## Enabling the functions

The functions are an extension of Caddy's built-in `templates` handler. They
are not available until the extension is named in the Caddyfile:

```caddyfile
templates {
	extensions {
		crypto
	}
}
```

The equivalent JSON is the `crypto` key in the handler's `extensions` map:

```json
{
	"handler": "templates",
	"extensions": {"crypto": {}}
}
```

`caddy list-modules` includes
`http.handlers.templates.functions.crypto` when the plugin is built in.

Any template error, including a cryptographic failure, aborts rendering and
Caddy answers `500` unless `handle_errors` is configured. Verification is
fail-closed by design.

## cryptotoken

Mints a compact JWT: `base64url(header).base64url(payload).base64url(sig)`
with unpadded base64url (RFC 7515, RFC 7519, RFC 8037).

```gotemplate
{{ cryptotoken $secret $label }}
{{ cryptotoken $secret $label $ttl }}
{{ $claims | toJson | cryptotoken $secret $label }}
{{ $claims | toJson | cryptotoken $secret $label $ttl }}
```

| Argument | Required | Meaning |
|----------|----------|---------|
| `$secret` | yes | Signing secret. Must not be empty. |
| `$label` | yes | Key version label, written to the JWT header as `kid` and used for derivation. Must not be empty. |
| `$ttl` | no | Go duration string such as `15m` or `24h`. Invalid durations abort rendering. |
| piped value | no | JSON object string of claims, usually `dict ... | toJson`. |

The header is always exactly `{"alg":"EdDSA","kid":"<label>"}`.

Claims handling:

- Piped claims are decoded as a JSON object and re-marshaled canonically
  (object keys sorted). Values keep their JSON types: strings, numbers,
  booleans, arrays, and nested objects. Numbers are decoded with
  `json.Decoder.UseNumber`, so integers are not rewritten as floats.
- `iat` is set to the current UTC Unix time in seconds only when the caller
  did not supply it.
- When `$ttl` is supplied, `exp` is set to `iat + ttl` in seconds only when
  the caller did not supply `exp`. An explicit `exp` wins.
- An explicit non-numeric `iat` is an error when `$ttl` is used.
- No other claims are added, removed, or rewritten.

Argument disambiguation: with one optional argument, a value whose first
non-space character is `{` is treated as the claims object; anything else is
treated as the TTL. With two, the first is the TTL and the second (the piped
value) is the claims object. With no optional argument the payload starts
empty.

## cryptosign

```gotemplate
{{ cryptosign $secret $str }}
{{ $str | cryptosign $secret }}
```

Returns the lowercase hexadecimal HMAC-SHA256 of `$str` keyed with `$secret`.
The bytes are signed exactly as given: no trimming, no timestamp injection, no
header or payload wrapping. `$secret` must not be empty; `$str` may be empty.

Use it when the verifier expects `<timestamp>.<body>` or similar layouts,
composing the message in the template:

```gotemplate
{{ $t := now.Unix }}
{{ $signed := printf "%d.%s" $t $body | cryptosign $secret }}
```

## cryptocheck

`cryptocheck` has two modes, selected by the first argument.

### JWT verification

```gotemplate
{{ $claims := cryptocheck $token $secret }}
{{ $claims.sub }}
```

1. Splits the token into exactly three non-empty segments and base64url-decodes
   the header.
2. Requires `"alg"` to be `"EdDSA"` and requires a non-empty `"kid"`. The
   signing key is re-derived from `$secret` and that `kid`; a token minted
   under another label does not verify.
3. Verifies the Ed25519 signature over `header.payload` exactly as received.
4. Decodes the payload into a claims map with `UseNumber`.
5. Enforces time claims: `exp` must be strictly in the future and `nbf` must
   not be in the future. Non-numeric `exp`/`nbf` values make the token invalid.
   There is no built-in clock skew allowance.
6. Returns the claims map without header fields, so caller claims are never
   shadowed by `alg` or `kid`.

`$secret` must not be empty. Malformed tokens, signature mismatches, wrong
labels, expired tokens, and not-yet-valid tokens all return errors and abort
the template.

### Body / webhook verification

```gotemplate
{{ $v := cryptocheck "hmac" $secret $payload $sigHeader }}
{{ $v := cryptocheck "hmac" $secret $payload $sigHeader $toleranceSec }}
```

`$payload` is verified exactly as passed. Point it at the raw body bytes: do
not decode and re-marshal JSON, because key order and whitespace are part of
the message.

`$sigHeader` accepts two shapes:

| Shape | Signed string | Notes |
|-------|---------------|-------|
| `<hex>` | `$payload` | Lowercase or uppercase hex. Comma-separated digests are accepted for key rotation; any match succeeds. |
| `t=<unix>,v1=<hex>` | `<t>.<payload>` | Stripe-style. Extra `v1=` entries are accepted; unrelated keys are ignored. |

`$toleranceSec` is only valid with a timestamped header. It accepts an integer,
float, or numeric string, must not be negative, and requires
`|now - t| <= tolerance` in whole seconds. Supplying a tolerance with a bare
digest is an error rather than a silent no-op. Without a tolerance the
timestamp is still part of the signed string, but its age is not checked.

All digest comparisons use `hmac.Equal`. On success the function returns a map
with `payload` and, for timestamped headers, `timestamp` as an `int64`.
`$secret` must not be empty; an empty signature header is an error.

Because the comparison is constant time and any mismatch aborts rendering,
templates branch on failures through `handle_errors`, not on a boolean from
`cryptocheck`.

## Key derivation

Token signing keys are derived deterministically:

```
seed = HKDF-SHA256(
    ikm  = secret,
    salt = "caddy-cryptosign/v1",
    info = "caddy-cryptotoken:" + label,
    len  = 32,
)
key = ed25519.NewKeyFromSeed(seed)
```

The salt is a fixed domain separator, not a secret. Any verifier sharing the
secret and label can reproduce the key; a different label is a different key.
`cryptosign` uses the secret directly as the HMAC key and performs no
derivation.

## Security properties

- Empty secrets are rejected by every function; no key is ever derived from a
  zero-length secret.
- Secrets are provided per call by the template; the plugin stores none.
- Signature and digest comparisons use constant-time primitives
  (`ed25519.Verify`, `hmac.Equal`).
- Verification fails closed: a bad signature, expired token, stale webhook
  timestamp, invalid duration, or malformed claims aborts rendering with an
  error instead of returning a falsy value.
- Errors do not include the secret. Keep template error pages generic; Caddy's
  default error page does not echo the rendered input.

## Examples

Issue a token and read it back:

```gotemplate
{{ $token := dict "sub" "user-42" "scopes" (list "read" "write") | toJson | cryptotoken "app-secret" "v1" "15m" }}
{{ $claims := cryptocheck $token "app-secret" }}
{{ $claims.sub }} {{ range $claims.scopes }}{{ . }} {{ end }}
```

Verify a body signature, with `$body` already holding the exact bytes captured
before any handler parsed or rewrote them:

```gotemplate
{{ $sig := placeholder "http.request.header.Stripe-Signature" }}
{{ $v := cryptocheck "hmac" "webhook-secret" $body $sig 300 }}
received {{ $v.payload }}
```

Exact-string signing for an outbound webhook:

```gotemplate
{{ $ts := now.Unix }}
{{ $sig := printf "%d.%s" $ts $body | cryptosign "webhook-secret" }}
X-Signature: t={{ $ts }},v1={{ $sig }}
```

## Build and test

No host Go toolchain is used. All commands run in
`caddy:2.11.9-builder-alpine` (Go 1.27.4); `go.mod` declares `go 1.26.0` and
Caddy `v2.11.9`.

```sh
sh test/unit.sh     # gofmt, go vet, go test in the builder image
./build.sh          # builds <slug>:test from NOTICE
sh test/e2e.sh      # serves test/e2e/fixtures and compares exact bytes
```

`test/e2e.sh` mounts its own Caddyfile and site over the image, checks that the
module is registered and that the linked Caddy version matches `go.mod`, that
the shipped and fixture configs validate, that an unknown extension is
rejected, and that token signing, HMAC signing, Stripe-style verification, and
three failure pages produce exact-byte responses.

The race detector needs cgo and is run separately:

```sh
docker run --rm -v caddy-sf-mod:/mod -v "$PWD":/src -w /src \
  -e GOMODCACHE=/mod -e GOCACHE=/mod/gocache -e CGO_ENABLED=1 \
  caddy:2.11.9-builder-alpine \
  sh -c 'apk add --no-cache gcc musl-dev && go test -race -timeout=180s ./...'
```

## Image

`./build.sh` derives the tag from the first line of `NOTICE` and produces
`caddy-cryptosign:test`. The final stage is `scratch` and contains the Caddy
binary, toybox, CA certificates, timezone data, licenses, and `www/`.
`www/Caddyfile` is installed as `/etc/caddy/Caddyfile`; pass
`run --config /etc/caddy/Caddyfile --adapter caddyfile` to load it. That
shipped config serves static files and does not enable the crypto extension,
so mount your own Caddyfile to use the functions. Without `--config`, Caddy
starts with an empty configuration.

The image keeps Caddy's default admin endpoint (`localhost:2019`), which its
`HEALTHCHECK` polls. A config that disables or moves the admin endpoint reports
unhealthy.

## Layout

- `cryptosign.go`: the only Go file at the repository root; blank-imports the
  module package so its `init` registration runs in an `xcaddy` build.
- `pkg/crypto/`: token issuance and verification, HKDF derivation, HMAC
  signing and checking, and their unit tests.
- `pkg/tplfuncs/`: the Caddy module, template argument handling, and template
  execution tests.
- `test/unit.sh`: canonical unit layer in the builder image.
- `test/e2e.sh`: image-level checks with fixtures under
  `test/e2e/fixtures/`.
- `www/`: the Caddyfile shipped inside the image.
- `spec.md`: the design target; not a description of the shipped surface.

## Limitations

- Webhook verification takes the payload as a template argument. The plugin
  does not capture and expose the raw request body itself, so the template must
  already have those exact bytes.
- JWT verification has no clock-skew allowance and no keyring/`kid` rotation
  lookup; the label in the token must equal the label used to derive the key.
- Verification failures are always fatal to the template. There is no soft
  "unauthenticated" return value.
- Token payloads are re-marshaled canonically; signing a pre-serialized JSON
  string byte-for-byte is what `cryptosign` is for.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
