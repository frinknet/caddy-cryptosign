// Package tplfuncs registers the crypto template functions with Caddy's
// templates handler as the http.handlers.templates.functions.crypto extension
// module.
package tplfuncs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/templates"

	"github.com/frinknet/caddy-cryptosign/pkg/crypto"
)

func init() {
	caddy.RegisterModule(Crypto{})
}

// Crypto is the extension module that provides cryptotoken, cryptosign, and
// cryptocheck. It has no configuration; secrets are passed per call.
type Crypto struct{}

// CaddyModule returns the Caddy module information.
func (Crypto) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.templates.functions.crypto",
		New: func() caddy.Module { return new(Crypto) },
	}
}

// CustomTemplateFunctions returns the template function map for the module.
func (Crypto) CustomTemplateFunctions() template.FuncMap {
	return template.FuncMap{
		"cryptotoken": issueToken,
		"cryptosign":  signHMAC,
		"cryptocheck": check,
	}
}

// UnmarshalCaddyfile accepts the bare extension name:
//
//	extensions {
//		crypto
//	}
func (Crypto) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	if d.NextBlock(d.Nesting()) {
		return d.Err("crypto takes no arguments")
	}
	return nil
}

// issueToken implements
//
//	{{ cryptotoken $secret $label [$ttl] }}
//	{{ $claims | toJson | cryptotoken $secret $label [$ttl] }}
func issueToken(secret, label string, args ...any) (string, error) {
	ttl, claims, err := tokenArgs(args)
	if err != nil {
		return "", err
	}
	return crypto.IssueToken(secret, label, claims, ttl, time.Now())
}

func tokenArgs(args []any) (ttl, claims string, err error) {
	switch len(args) {
	case 0:
		return "", "", nil
	case 1:
		s, err := stringArg(args[0])
		if err != nil {
			return "", "", fmt.Errorf("cryptotoken: %w", err)
		}
		if strings.HasPrefix(strings.TrimSpace(s), "{") {
			return "", s, nil
		}
		return s, "", nil
	case 2:
		ttl, err := stringArg(args[0])
		if err != nil {
			return "", "", fmt.Errorf("cryptotoken: ttl: %w", err)
		}
		claims, err := stringArg(args[1])
		if err != nil {
			return "", "", fmt.Errorf("cryptotoken: claims: %w", err)
		}
		return ttl, claims, nil
	default:
		return "", "", fmt.Errorf("cryptotoken: at most a ttl and a claims object are accepted, got %d arguments", len(args))
	}
}

// signHMAC implements
//
//	{{ cryptosign $secret $str }}
//	{{ $str | cryptosign $secret }}
func signHMAC(secret, payload string) (string, error) {
	return crypto.SignHMAC(secret, payload)
}

// check implements
//
//	{{ cryptocheck $token $secret }}
//	{{ cryptocheck "jwt" $token $secret [$options] }}
//	{{ cryptocheck "hmac" $secret $payload $sigHeader [$toleranceSec] }}
func check(args ...any) (map[string]any, error) {
	if len(args) == 0 {
		return nil, errors.New("cryptocheck: missing arguments")
	}
	if mode, ok := args[0].(string); ok {
		switch mode {
		case "hmac":
			return checkHMAC(args[1:])
		case "jwt":
			return checkJWT(args[1:])
		}
	}

	if len(args) != 2 {
		return nil, fmt.Errorf("cryptocheck: expected a token and a secret, got %d arguments", len(args))
	}
	token, err := stringArg(args[0])
	if err != nil {
		return nil, fmt.Errorf("cryptocheck: token: %w", err)
	}
	secret, err := stringArg(args[1])
	if err != nil {
		return nil, fmt.Errorf("cryptocheck: secret: %w", err)
	}
	return crypto.CheckToken(token, secret, time.Now())
}

// checkJWT implements the options-aware JWT mode:
//
//	{{ cryptocheck "jwt" $token $secret [$optionsJSON] }}
//
// Options: skew (seconds), iss, aud, typ, soft (bool). A soft check returns a
// nil claims map and no error when the token cannot be verified, which lets a
// template render an unauthenticated view. An empty secret is always a hard
// error.
func checkJWT(args []any) (map[string]any, error) {
	if len(args) < 2 || len(args) > 3 {
		return nil, fmt.Errorf("cryptocheck jwt: expected a token, a secret, and optional options, got %d arguments", len(args))
	}
	token, err := stringArg(args[0])
	if err != nil {
		return nil, fmt.Errorf("cryptocheck jwt: token: %w", err)
	}
	secret, err := stringArg(args[1])
	if err != nil {
		return nil, fmt.Errorf("cryptocheck jwt: secret: %w", err)
	}
	if secret == "" {
		return nil, crypto.ErrEmptySecret
	}

	var (
		opts crypto.CheckOptions
		soft bool
	)
	if len(args) == 3 {
		optionsJSON, err := stringArg(args[2])
		if err != nil {
			return nil, fmt.Errorf("cryptocheck jwt: options: %w", err)
		}
		opts, soft, err = parseCheckOptions(optionsJSON)
		if err != nil {
			return nil, fmt.Errorf("cryptocheck jwt: options: %w", err)
		}
	}

	claims, err := crypto.CheckTokenWithOptions(token, secret, opts, time.Now())
	if err != nil {
		if soft {
			return nil, nil
		}
		return nil, err
	}
	return claims, nil
}

func parseCheckOptions(optionsJSON string) (crypto.CheckOptions, bool, error) {
	var opts crypto.CheckOptions
	dec := json.NewDecoder(strings.NewReader(optionsJSON))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return opts, false, fmt.Errorf("invalid options JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return opts, false, errors.New("invalid options JSON: trailing data")
	}

	soft := false
	for key, value := range raw {
		switch key {
		case "skew":
			seconds, err := secondsArg(value)
			if err != nil {
				return opts, false, fmt.Errorf("skew: %w", err)
			}
			if seconds < 0 {
				return opts, false, errors.New("skew must not be negative")
			}
			opts.Skew = time.Duration(seconds * float64(time.Second))
		case "iss":
			s, err := stringArg(value)
			if err != nil {
				return opts, false, fmt.Errorf("iss: %w", err)
			}
			opts.Issuer = s
		case "aud":
			s, err := stringArg(value)
			if err != nil {
				return opts, false, fmt.Errorf("aud: %w", err)
			}
			opts.Audience = s
		case "typ":
			s, err := stringArg(value)
			if err != nil {
				return opts, false, fmt.Errorf("typ: %w", err)
			}
			opts.Type = s
		case "soft":
			b, ok := value.(bool)
			if !ok {
				return opts, false, fmt.Errorf("soft: expected a boolean, got %T", value)
			}
			soft = b
		default:
			return opts, false, fmt.Errorf("unknown option %q", key)
		}
	}
	return opts, soft, nil
}

func checkHMAC(args []any) (map[string]any, error) {
	if len(args) < 3 || len(args) > 4 {
		return nil, fmt.Errorf("cryptocheck hmac: expected secret, payload, signature, and optional tolerance, got %d arguments", len(args))
	}
	secret, err := stringArg(args[0])
	if err != nil {
		return nil, fmt.Errorf("cryptocheck hmac: secret: %w", err)
	}
	payload, err := stringArg(args[1])
	if err != nil {
		return nil, fmt.Errorf("cryptocheck hmac: payload: %w", err)
	}
	sigHeader, err := stringArg(args[2])
	if err != nil {
		return nil, fmt.Errorf("cryptocheck hmac: signature: %w", err)
	}

	var tolerance time.Duration
	if len(args) == 4 {
		seconds, err := secondsArg(args[3])
		if err != nil {
			return nil, fmt.Errorf("cryptocheck hmac: tolerance: %w", err)
		}
		tolerance = time.Duration(seconds * float64(time.Second))
	}

	return crypto.CheckHMAC(secret, payload, sigHeader, tolerance, time.Now())
}

func stringArg(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("expected a string, got %T", v)
	}
	return s, nil
}

func secondsArg(v any) (float64, error) {
	var seconds float64
	switch n := v.(type) {
	case int:
		seconds = float64(n)
	case int64:
		seconds = float64(n)
	case float64:
		seconds = n
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, fmt.Errorf("expected seconds, got %q", n)
		}
		seconds = f
	case string:
		f, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0, fmt.Errorf("expected seconds, got %q", n)
		}
		seconds = f
	default:
		return 0, fmt.Errorf("expected seconds, got %T", v)
	}
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return 0, errors.New("expected a finite number of seconds")
	}
	if limit := float64(math.MaxInt64) / float64(time.Second); seconds > limit || seconds < -limit {
		return 0, errors.New("tolerance is too large")
	}
	return seconds, nil
}

var (
	_ caddy.Module              = Crypto{}
	_ caddyfile.Unmarshaler     = Crypto{}
	_ templates.CustomFunctions = Crypto{}
)
