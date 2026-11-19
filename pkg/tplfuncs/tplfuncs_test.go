package tplfuncs

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/frinknet/caddy-cryptosign/pkg/crypto"
)

func render(t *testing.T, source string, data any) (string, error) {
	t.Helper()
	tpl, err := template.New("test").Funcs(Crypto{}.CustomTemplateFunctions()).Parse(source)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var out strings.Builder
	err = tpl.Execute(&out, data)
	return out.String(), err
}

func renderOK(t *testing.T, source string, data any) string {
	t.Helper()
	out, err := render(t, source, data)
	if err != nil {
		t.Fatalf("execute %q: %v", source, err)
	}
	return out
}

func TestCryptosign(t *testing.T) {
	const want = "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"
	if got := renderOK(t, `{{ cryptosign "secret" "hello" }}`, nil); got != want {
		t.Fatalf("got %s", got)
	}
	if got := renderOK(t, `{{ "hello" | cryptosign "secret" }}`, nil); got != want {
		t.Fatalf("piped: got %s", got)
	}
}

func TestCryptotokenPipedClaims(t *testing.T) {
	source := `{{ $t := "{\"sub\":\"alice\",\"n\":7}" | cryptotoken "s3cr3t" "v1" "1h" }}` +
		`{{ $c := cryptocheck $t "s3cr3t" }}{{ $c.sub }}/{{ $c.n }}`
	if got := renderOK(t, source, nil); got != "alice/7" {
		t.Fatalf("got %q", got)
	}
}

func TestCryptotokenPipedClaimsWithoutTTL(t *testing.T) {
	source := `{{ $t := "{\"sub\":\"bob\"}" | cryptotoken "s3cr3t" "v1" }}` +
		`{{ $c := cryptocheck $t "s3cr3t" }}{{ $c.sub }}`
	if got := renderOK(t, source, nil); got != "bob" {
		t.Fatalf("got %q", got)
	}
}

func TestCryptotokenTTLArgument(t *testing.T) {
	source := `{{ $t := cryptotoken "s3cr3t" "v1" "15m" }}{{ $c := cryptocheck $t "s3cr3t" }}{{ $c.exp }}`
	out := renderOK(t, source, nil)
	exp, err := strconv.ParseInt(out, 10, 64)
	if err != nil {
		t.Fatalf("exp %q: %v", out, err)
	}
	if d := exp - time.Now().Unix(); d < 890 || d > 910 {
		t.Fatalf("exp is %d seconds away, want about 900", d)
	}
}

func TestCryptocheckHMACArgument(t *testing.T) {
	payload := `{"event":"paid"}`
	digest, err := crypto.SignHMAC("s3cr3t", payload)
	if err != nil {
		t.Fatalf("SignHMAC: %v", err)
	}
	source := `{{ $v := cryptocheck "hmac" "s3cr3t" ` + strconv.Quote(payload) + ` "` + digest + `" }}{{ $v.payload }}`
	if got := renderOK(t, source, nil); got != payload {
		t.Fatalf("got %q", got)
	}
}

func TestCryptocheckHMACStripeStyle(t *testing.T) {
	const payload = "body"
	ts := time.Now().Unix()
	digest, err := crypto.SignHMAC("s3cr3t", strconv.FormatInt(ts, 10)+"."+payload)
	if err != nil {
		t.Fatalf("SignHMAC: %v", err)
	}
	header := "t=" + strconv.FormatInt(ts, 10) + ",v1=" + digest
	source := `{{ $v := cryptocheck "hmac" "s3cr3t" "` + payload + `" "` + header + `" 60 }}{{ $v.timestamp }}`
	if got := renderOK(t, source, nil); got != strconv.FormatInt(ts, 10) {
		t.Fatalf("timestamp = %q, want %d", got, ts)
	}
}

func TestCryptocheckJWTMode(t *testing.T) {
	source := `{{ $t := "{\"sub\":\"alice\"}" | cryptotoken "s3cr3t" "v1" "1h" }}` +
		`{{ $c := cryptocheck "jwt" $t "s3cr3t" }}{{ $c.sub }}`
	if got := renderOK(t, source, nil); got != "alice" {
		t.Fatalf("got %q", got)
	}
}

func TestCryptocheckJWTPolicy(t *testing.T) {
	source := `{{ $t := "{\"sub\":\"alice\",\"iss\":\"auth.example\",\"aud\":\"api\"}" | cryptotoken "s3cr3t" "v1" "1h" }}` +
		`{{ $c := cryptocheck "jwt" $t "s3cr3t" "{\"iss\":\"auth.example\",\"aud\":\"api\"}" }}{{ $c.sub }}`
	if got := renderOK(t, source, nil); got != "alice" {
		t.Fatalf("got %q", got)
	}

	for _, options := range []string{
		`{"iss":"other.example"}`,
		`{"aud":"admin"}`,
		`{"typ":"JWT"}`,
		`{"skew":-1}`,
		`{"unknown":1}`,
		`[1]`,
		`{"soft":"yes"}`,
	} {
		t.Run(options, func(t *testing.T) {
			src := `{{ $t := "{\"sub\":\"alice\",\"iss\":\"auth.example\"}" | cryptotoken "s3cr3t" "v1" "1h" }}` +
				`{{ cryptocheck "jwt" $t "s3cr3t" ` + strconv.Quote(options) + ` }}`
			if _, err := render(t, src, nil); err == nil {
				t.Fatal("template succeeded, want error")
			}
		})
	}
}

func TestCryptocheckJWTSkewAndSoft(t *testing.T) {
	source := `{{ $t := "{\"sub\":\"alice\"}" | cryptotoken "s3cr3t" "v1" "-1s" }}` +
		`{{ $c := cryptocheck "jwt" $t "s3cr3t" "{\"skew\":60}" }}{{ $c.sub }}`
	if got := renderOK(t, source, nil); got != "alice" {
		t.Fatalf("skewed check: got %q", got)
	}

	soft := `{{ $t := "{\"sub\":\"alice\"}" | cryptotoken "s3cr3t" "v1" "-1s" }}` +
		`{{ $c := cryptocheck "jwt" $t "s3cr3t" "{\"soft\":true}" }}` +
		`{{ if $c }}signed in{{ else }}anonymous{{ end }}`
	if got := renderOK(t, soft, nil); got != "anonymous" {
		t.Fatalf("soft check: got %q", got)
	}

	// A soft check still treats an empty secret as a hard error.
	hard := `{{ cryptocheck "jwt" "not.a.token" "" "{\"soft\":true}" }}`
	if _, err := render(t, hard, nil); err == nil {
		t.Fatal("soft check accepted an empty secret")
	}

	// Without soft, the same expired token aborts the template.
	abort := `{{ $t := "{\"sub\":\"alice\"}" | cryptotoken "s3cr3t" "v1" "-1s" }}{{ cryptocheck "jwt" $t "s3cr3t" }}`
	if _, err := render(t, abort, nil); err == nil {
		t.Fatal("expired token rendered without soft")
	}
}

func TestFailuresAbortTemplate(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{name: "empty sign secret", source: `{{ cryptosign "" "hello" }}`},
		{name: "empty token secret", source: `{{ cryptotoken "" "v1" }}`},
		{name: "empty label", source: `{{ cryptotoken "s3cr3t" "" }}`},
		{name: "bad ttl", source: `{{ cryptotoken "s3cr3t" "v1" "soon" }}`},
		{name: "bad claims", source: `{{ cryptotoken "s3cr3t" "v1" "[1]" }}`},
		{name: "bad token", source: `{{ cryptocheck "not.a.token" "s3cr3t" }}`},
		{name: "wrong hmac", source: `{{ cryptocheck "hmac" "s3cr3t" "body" "deadbeef" }}`},
		{name: "hmac empty secret", source: `{{ cryptocheck "hmac" "" "body" "deadbeef" }}`},
		{name: "too many hmac args", source: `{{ cryptocheck "hmac" "a" "b" "c" 1 2 }}`},
		{name: "non-string argument", source: `{{ cryptosign 42 "hello" }}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := render(t, tt.source, nil); err == nil {
				t.Fatal("template succeeded, want error")
			}
		})
	}
}

func TestTokenArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []any
		wantTTL    string
		wantClaims string
		wantErr    bool
	}{
		{name: "none"},
		{name: "ttl", args: []any{"5m"}, wantTTL: "5m"},
		{name: "claims", args: []any{` {"a":1}`}, wantClaims: ` {"a":1}`},
		{name: "ttl and claims", args: []any{"5m", `{"a":1}`}, wantTTL: "5m", wantClaims: `{"a":1}`},
		{name: "too many", args: []any{"5m", "{}", "extra"}, wantErr: true},
		{name: "not a string", args: []any{json.Number("5")}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ttl, claims, err := tokenArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("tokenArgs: %v", err)
			}
			if ttl != tt.wantTTL || claims != tt.wantClaims {
				t.Fatalf("got (%q, %q), want (%q, %q)", ttl, claims, tt.wantTTL, tt.wantClaims)
			}
		})
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	for _, input := range []string{"crypto", "crypto\n"} {
		d := caddyfile.NewTestDispenser(input)
		if err := (Crypto{}).UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("UnmarshalCaddyfile(%q): %v", input, err)
		}
	}
	for _, input := range []string{"crypto extra", "crypto {\n\tx\n}"} {
		d := caddyfile.NewTestDispenser(input)
		if err := (Crypto{}).UnmarshalCaddyfile(d); err == nil {
			t.Fatalf("UnmarshalCaddyfile(%q) accepted arguments", input)
		}
	}
}

func TestSecondsArg(t *testing.T) {
	for _, v := range []any{60, int64(60), float64(60), json.Number("60"), "60"} {
		got, err := secondsArg(v)
		if err != nil {
			t.Fatalf("secondsArg(%T): %v", v, err)
		}
		if got != 60 {
			t.Fatalf("secondsArg(%T) = %v", v, got)
		}
	}
	for _, v := range []any{nil, true, "soon", "NaN"} {
		if _, err := secondsArg(v); err == nil {
			t.Fatalf("secondsArg(%v) accepted", v)
		}
	}
}
