package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func signRawToken(t *testing.T, secret, label, headerJSON, payloadJSON string) string {
	t.Helper()
	key, err := DeriveKey(secret, label)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	h64 := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	p64 := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	sig := ed25519.Sign(key, []byte(h64+"."+p64))
	return h64 + "." + p64 + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestCheckTokenSkew(t *testing.T) {
	now := time.Unix(testNow, 0)
	token, err := IssueToken(testSecret, "v1", `{"sub":"alice"}`, "1h", now)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	pastExpiry := now.Add(time.Hour + 30*time.Second)
	if _, err := CheckTokenWithOptions(token, testSecret, CheckOptions{}, pastExpiry); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("no skew error = %v, want ErrExpiredToken", err)
	}
	if _, err := CheckTokenWithOptions(token, testSecret, CheckOptions{Skew: time.Minute}, pastExpiry); err != nil {
		t.Fatalf("token should be valid inside the skew: %v", err)
	}

	// exp + skew is the boundary and is already expired.
	edge := now.Add(time.Hour + time.Minute)
	if _, err := CheckTokenWithOptions(token, testSecret, CheckOptions{Skew: time.Minute}, edge); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("boundary error = %v, want ErrExpiredToken", err)
	}

	notYet, err := IssueToken(testSecret, "v1", `{"nbf":1700000600}`, "", now)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	beforeNbf := time.Unix(1700000600, 0).Add(-55 * time.Second)
	if _, err := CheckTokenWithOptions(notYet, testSecret, CheckOptions{Skew: time.Minute}, beforeNbf); err != nil {
		t.Fatalf("token should be valid inside the skew: %v", err)
	}
	if _, err := CheckTokenWithOptions(notYet, testSecret, CheckOptions{Skew: 30 * time.Second}, beforeNbf); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("error = %v, want ErrNotYetValid", err)
	}

	if _, err := CheckTokenWithOptions(token, testSecret, CheckOptions{Skew: -time.Second}, now); err == nil {
		t.Fatal("negative skew accepted")
	}
}

func TestCheckTokenPolicy(t *testing.T) {
	now := time.Unix(testNow, 0)

	token, err := IssueToken(testSecret, "v1", `{"sub":"alice","iss":"auth.example","aud":["api","web"]}`, "", now)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	opts := CheckOptions{Issuer: "auth.example", Audience: "api"}
	if _, err := CheckTokenWithOptions(token, testSecret, opts, now); err != nil {
		t.Fatalf("policy should pass: %v", err)
	}
	if _, err := CheckTokenWithOptions(token, testSecret, CheckOptions{Audience: "web"}, now); err != nil {
		t.Fatalf("audience array should match: %v", err)
	}

	failures := []CheckOptions{
		{Issuer: "other.example"},
		{Audience: "admin"},
		{Issuer: "auth.example", Audience: "admin"},
	}
	for _, o := range failures {
		if _, err := CheckTokenWithOptions(token, testSecret, o, now); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("opts %+v error = %v, want ErrInvalidToken", o, err)
		}
	}

	// A string aud matches exactly, and a non-string iss never does.
	stringAud := signRawToken(t, testSecret, "v1", `{"alg":"EdDSA","kid":"v1"}`, `{"aud":"api"}`)
	if _, err := CheckTokenWithOptions(stringAud, testSecret, CheckOptions{Audience: "api"}, now); err != nil {
		t.Fatalf("string aud: %v", err)
	}
	badIss := signRawToken(t, testSecret, "v1", `{"alg":"EdDSA","kid":"v1"}`, `{"iss":7}`)
	if _, err := CheckTokenWithOptions(badIss, testSecret, CheckOptions{Issuer: "auth.example"}, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("non-string iss error = %v", err)
	}
}

func TestCheckTokenTyp(t *testing.T) {
	now := time.Unix(testNow, 0)
	withTyp := signRawToken(t, testSecret, "v1", `{"alg":"EdDSA","kid":"v1","typ":"JWT"}`, `{"sub":"alice"}`)

	if _, err := CheckTokenWithOptions(withTyp, testSecret, CheckOptions{Type: "JWT"}, now); err != nil {
		t.Fatalf("typ JWT: %v", err)
	}
	if _, err := CheckTokenWithOptions(withTyp, testSecret, CheckOptions{Type: "at+jwt"}, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("typ mismatch error = %v", err)
	}

	// cryptotoken emits no typ header, so requiring one rejects its tokens.
	issued, err := IssueToken(testSecret, "v1", "", "", now)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if _, err := CheckTokenWithOptions(issued, testSecret, CheckOptions{Type: "JWT"}, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("missing typ error = %v", err)
	}
}
