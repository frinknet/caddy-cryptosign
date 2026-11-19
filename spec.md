# Specification: Caddy Template Cryptographic Primitives

This specification defines three Caddy-native template functions for stateless token issuance, payload signing, and verification: **`cryptotoken`**, **`cryptosign`**, and **`cryptocheck`**.

Secrets are passed explicitly at call time from the application/template layer rather than locked behind a single server-global seed, keeping key scoping and rotation under template/app control.

---

## 1. Key Derivation & General Rules

* **Non-empty secret requirement:** All three functions MUST reject an empty secret with an error. Never silently sign or verify with a zero-length key.
* **HKDF-SHA256 Ed25519 derivation (for `cryptotoken` / JWT `cryptocheck`):**
* Given a caller secret `S` and a plain version/key label `label` (e.g., `"v1"`, `"v2"`—no `"kid:"` prefix required in the call), derive a deterministic 32-byte seed via HKDF-SHA256 (`ikm = S`, `info = "caddy-cryptotoken:" + label`, `salt = nil` or fixed domain salt) and construct the Ed25519 keypair via `ed25519.NewKeyFromSeed(seed)`.
* The `label` is written directly to the JWT protected header as `"kid"`.


* **Constant-time comparison:** Any HMAC or signature digest comparison MUST use constant-time comparison (`hmac.Equal` / `subtle.ConstantTimeCompare`).
* **Raw byte & string fidelity:** Signing and verification operate on exact byte sequences without re-encoding, trimming, or mutating whitespace/JSON field ordering.

---

## 2. `cryptotoken` — Standard EdDSA (Ed25519) JWT Issuer

Mints a compact JWT (`base64url(header).base64url(payload).base64url(signature)`, unpadded per RFC 7515 / RFC 7519 / RFC 8037).

### Template Signatures

```gotemplate
{{ $claims | toJson | cryptotoken $secret $label [$ttl] }}
{{ cryptotoken $secret $label [$ttl] }}

```

* **`$secret` (string, required):** Signing secret held by the app/template context.
* **`$label` (string, required):** Key version/derivation label (e.g., `"v1"`). Placed in JWT header `"kid"` and used as the HKDF derivation label.
* **`$ttl` (string, optional):** Go duration string (e.g., `"15m"`, `"24h"`). When provided, sets numeric `exp` (`iat + int64(duration.Seconds())`).
* **Piped input (optional):** JSON object string (typically `dict ... | toJson`) containing custom/standard claims. If omitted or empty, starts with an empty claims object `{}`.

### Standard Ordering & Claim Rules

1. **Header object:**
* `"alg"`: `"EdDSA"` (RFC 8037).
* `"kid"`: `$label` (when non-empty).


2. **Payload / Claims object:**
* Decode piped JSON object into a map/ordered representation.
* Set `"iat"` to current UTC Unix epoch seconds (`int64`) if not already explicitly provided.
* If `$ttl` is supplied, parse duration (`time.ParseDuration`), error on invalid duration, and set `"exp"` to `iat + int64(ttl.Seconds())` (unless explicitly set, or follow explicit override rules).
* Preserve all caller claims (strings, numbers, booleans, arrays, nested objects) as standard JSON types.


3. **Signing pipeline (strict order):**
* Base64url-encode (no `=`) marshaled header JSON $\rightarrow$ `h64`.
* Base64url-encode (no `=`) marshaled payload JSON $\rightarrow$ `p64`.
* Construct signing input ASCII bytes: `h64 + "." + p64`.
* Sign with HKDF-derived Ed25519 private key $\rightarrow$ `sig`.
* Base64url-encode (no `=`) `sig` $\rightarrow$ `s64`.
* Return `h64 + "." + p64 + "." + s64`.



---

## 3. `cryptosign` — Minimal HMAC-SHA256 String Signer

Computes a lowercase hexadecimal HMAC-SHA256 digest over an exact string/payload. Timestamp formatting and payload composition stay in the template via `printf` or upstream variables.

### Template Signatures

```gotemplate
{{ cryptosign $secret $str }}
{{ $str | cryptosign $secret }}

```

* **`$secret` (string, required):** HMAC key/secret.
* **`$str` (string, required via arg or pipe):** Exact string to sign (for example, `printf "%d.%s" $t $body`).

### Behavior

* Computes `HMAC-SHA256(key=[]byte($secret), data=[]byte($str))`.
* Returns lowercase hex string (`hex.EncodeToString(mac)`).
* Performs no timestamp injection, header wrapping, or payload mutation.

---

## 4. `cryptocheck` — Unified JWT & Body/Webhook Verifier

Verifies either:

1. **EdDSA JWTs** minted by `cryptotoken` (or compatible EdDSA tokens), returning a decoded claims map for dot-access in templates; or
2. **HMAC / Webhook body signatures** (such as `<timestamp>.<raw_body>` / `Stripe-Signature` schemes), enforcing signature integrity and optional timestamp tolerance.

### Mode A: JWT Verification

```gotemplate
{{ $claims := cryptocheck $token $secret }}

```

1. Split `$token` into 3 dot-separated segments (`h64`, `p64`, `s64`); fail if malformed.
2. Base64url-decode `h64` and verify `"alg" == "EdDSA"`. Extract `"kid"` (e.g., `"v1"`).
3. Derive Ed25519 public key via HKDF-SHA256 from `$secret` + `kid`.
4. Verify Ed25519 signature over `[]byte(h64 + "." + p64)` against decoded `s64`.
5. Base64url-decode `p64` into claims map (`map[string]any`).
6. Validate time claims (`exp` if present must be in the future; `nbf` if present must not be in the future; optional clock skew allowance).
7. Return the claims map (including header `kid` if helpful and non-colliding) so templates can read fields like `{{ $claims.sub }}` or `{{ $claims.appdata }}`.

### Mode B: Body / Webhook Signature Verification

```gotemplate
{{ cryptocheck "hmac" $secret $payload $sigHeader [$toleranceSec] }}

```

*(Or structured options/args matching timestamp + raw body + signature header.)*

1. Preserve exact raw bytes of `$payload` (and timestamp `t` when using `<t>.<body>` schemes like Stripe's `t=<ts>,v1=<hex>`).
2. If a timestamp and tolerance window are provided, parse Unix timestamp `t` and verify `|now - t| <= tolerance`.
3. Compute expected HMAC-SHA256 over the exact signed string (e.g., `"<t>.<raw_body>"` or `"<raw_body>"`) using `$secret`.
4. Compare expected digest against candidate signature(s) in constant time (`hmac.Equal`).
5. Return verified result/parsed payload on success.

---

## 5. Open Decisions to Finalize Before Coding

1. **Failure return semantics (`error` vs. `nil`):**
* **Hard fail (`return nil, err`):** Halts template execution immediately on bad signature, expired token, or stale webhook timestamp (recommended for protected/webhook endpoints).
* **Soft fail (`return nil, nil`):** Allows templates to branch with `{{ if $claims }}` for optional/public views where an expired or missing token simply means unauthenticated.
* *Option:* Make `cryptocheck` return `(map[string]any, error)` by default on cryptographic/structural errors, or provide a soft-check variant/flag if optional auth rendering is needed.


2. **Raw request body access in Caddy templates:**
* Ensure the raw request body bytes are captured prior to any parsing/middleware mutation and passed verbatim (avoiding re-marshaling JSON maps, which can alter key order or whitespace and break HMAC verification).
