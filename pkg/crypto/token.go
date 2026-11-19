package crypto

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	// tokenInfoPrefix scopes HKDF output to token signing so the same
	// secret cannot be reused for another purpose with the same label.
	tokenInfoPrefix = "caddy-cryptotoken:"
	// derivationSalt is a fixed domain salt. It is not secret; it only
	// separates this plugin's derivations from other HKDF users.
	derivationSalt = "caddy-cryptosign/v1"
	// algEdDSA is the only accepted JWT algorithm (RFC 8037).
	algEdDSA = "EdDSA"
)

type tokenHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// DeriveKey returns the Ed25519 private key for secret and label. An empty
// secret or label is an error; a key is never derived from a zero-length
// secret.
func DeriveKey(secret, label string) (ed25519.PrivateKey, error) {
	if secret == "" {
		return nil, ErrEmptySecret
	}
	if label == "" {
		return nil, ErrEmptyLabel
	}
	seed, err := hkdf.Key(sha256.New, []byte(secret), []byte(derivationSalt), tokenInfoPrefix+label, ed25519.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("cryptosign: derive key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// IssueToken mints a compact EdDSA JWT. claimsJSON is an optional JSON object;
// an empty string starts from {}. When ttl is non-empty it is parsed with
// time.ParseDuration and sets exp unless the caller already supplied one. iat
// defaults to now and is never overwritten.
func IssueToken(secret, label, claimsJSON, ttl string, now time.Time) (string, error) {
	key, err := DeriveKey(secret, label)
	if err != nil {
		return "", err
	}

	claims, err := decodeClaims(claimsJSON)
	if err != nil {
		return "", err
	}

	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now.UTC().Unix()
	}

	if ttl != "" {
		d, err := time.ParseDuration(ttl)
		if err != nil {
			return "", fmt.Errorf("cryptosign: invalid ttl %q: %w", ttl, err)
		}
		if _, ok := claims["exp"]; !ok {
			issued, err := intClaim(claims["iat"], "iat")
			if err != nil {
				return "", err
			}
			claims["exp"] = issued + int64(d.Seconds())
		}
	}

	headerJSON, err := json.Marshal(tokenHeader{Alg: algEdDSA, Kid: label})
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	h64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	p64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := h64 + "." + p64
	sig := ed25519.Sign(key, []byte(signingInput))

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// CheckOptions narrows what a verified token must contain. Zero values mean
// "do not check".
type CheckOptions struct {
	// Skew tolerates clock drift between issuer and verifier. It widens both
	// exp and nbf by the same amount. Negative values are rejected.
	Skew time.Duration
	// Issuer, when set, must equal the iss claim.
	Issuer string
	// Audience, when set, must be the aud claim or one of its entries.
	Audience string
	// Type, when set, must equal the typ header.
	Type string
}

// CheckToken verifies a compact EdDSA JWT and returns its claims. The signing
// key is re-derived from secret and the token's kid header. exp and nbf are
// enforced when present, with no clock skew allowance.
func CheckToken(token, secret string, now time.Time) (map[string]any, error) {
	return CheckTokenWithOptions(token, secret, CheckOptions{}, now)
}

// CheckTokenWithOptions is CheckToken with an explicit clock skew and claim
// policy. Verification is unchanged unless an option is set.
func CheckTokenWithOptions(token, secret string, opts CheckOptions, now time.Time) (map[string]any, error) {
	if secret == "" {
		return nil, ErrEmptySecret
	}
	if opts.Skew < 0 {
		return nil, fmt.Errorf("cryptosign: clock skew must not be negative")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("%w: expected three non-empty segments", ErrInvalidToken)
	}
	h64, p64, s64 := parts[0], parts[1], parts[2]

	headerJSON, err := base64.RawURLEncoding.DecodeString(h64)
	if err != nil {
		return nil, fmt.Errorf("%w: header is not base64url: %v", ErrInvalidToken, err)
	}
	var header tokenHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: header is not JSON: %v", ErrInvalidToken, err)
	}
	if header.Alg != algEdDSA {
		return nil, fmt.Errorf("%w: alg %q is not %s", ErrInvalidToken, header.Alg, algEdDSA)
	}
	if header.Kid == "" {
		return nil, fmt.Errorf("%w: kid is missing", ErrInvalidToken)
	}
	if opts.Type != "" && header.Typ != opts.Type {
		return nil, fmt.Errorf("%w: typ %q is not %q", ErrInvalidToken, header.Typ, opts.Type)
	}

	key, err := DeriveKey(secret, header.Kid)
	if err != nil {
		return nil, err
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: derived key is not Ed25519", ErrInvalidToken)
	}

	sig, err := base64.RawURLEncoding.DecodeString(s64)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not base64url: %v", ErrInvalidToken, err)
	}
	if !ed25519.Verify(pub, []byte(h64+"."+p64), sig) {
		return nil, fmt.Errorf("%w: signature mismatch", ErrInvalidToken)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(p64)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url: %v", ErrInvalidToken, err)
	}
	claims, err := decodeClaims(string(payloadJSON))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if opts.Issuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != opts.Issuer {
			return nil, fmt.Errorf("%w: iss %q is not %q", ErrInvalidToken, iss, opts.Issuer)
		}
	}
	if opts.Audience != "" && !audienceMatches(claims["aud"], opts.Audience) {
		return nil, fmt.Errorf("%w: aud does not include %q", ErrInvalidToken, opts.Audience)
	}

	nowSeconds := float64(now.UTC().UnixNano()) / float64(time.Second)
	skewSeconds := opts.Skew.Seconds()
	if v, ok := claims["exp"]; ok {
		exp, err := numberClaim(v, "exp")
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
		if nowSeconds >= exp+skewSeconds {
			return nil, ErrExpiredToken
		}
	}
	if v, ok := claims["nbf"]; ok {
		nbf, err := numberClaim(v, "nbf")
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
		if nowSeconds+skewSeconds < nbf {
			return nil, ErrNotYetValid
		}
	}

	return claims, nil
}

// audienceMatches reports whether the aud claim (a string or an array of
// strings, per RFC 7519) contains want.
func audienceMatches(v any, want string) bool {
	switch aud := v.(type) {
	case string:
		return aud == want
	case []any:
		for _, item := range aud {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func decodeClaims(claimsJSON string) (map[string]any, error) {
	claims := map[string]any{}
	if claimsJSON == "" {
		return claims, nil
	}

	dec := json.NewDecoder(strings.NewReader(claimsJSON))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("cryptosign: invalid claims JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("cryptosign: invalid claims JSON: trailing data")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("cryptosign: claims must be a JSON object")
	}
	return m, nil
}

func numberClaim(v any, name string) (float64, error) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, fmt.Errorf("cryptosign: claim %q is not a number", name)
		}
		return f, nil
	case float64:
		return n, nil
	case int64:
		return float64(n), nil
	case int:
		return float64(n), nil
	default:
		return 0, fmt.Errorf("cryptosign: claim %q is not a number", name)
	}
}

func intClaim(v any, name string) (int64, error) {
	switch n := v.(type) {
	case json.Number:
		i, err := strconv.ParseInt(n.String(), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("cryptosign: claim %q is not an integer", name)
		}
		return i, nil
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	default:
		return 0, fmt.Errorf("cryptosign: claim %q is not an integer", name)
	}
}
