package crypto

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testSecret = "correct horse battery staple"
	testNow    = int64(1700000000)
)

func TestDeriveKeyIsDeterministic(t *testing.T) {
	now := time.Unix(testNow, 0)

	first, err := IssueToken(testSecret, "v1", "", "", now)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	second, err := IssueToken(testSecret, "v1", "", "", now)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if first != second {
		t.Fatalf("same inputs produced different tokens:\n%s\n%s", first, second)
	}
}

func TestDeriveKeyMatchesSpec(t *testing.T) {
	key, err := DeriveKey(testSecret, "v1")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	seed, err := hkdf.Key(sha256.New, []byte(testSecret), []byte(derivationSalt), "caddy-cryptotoken:v1", ed25519.SeedSize)
	if err != nil {
		t.Fatalf("hkdf.Key: %v", err)
	}
	if string(key.Seed()) != string(seed) {
		t.Fatal("derived seed does not match the documented HKDF inputs")
	}
	if len(key) != ed25519.PrivateKeySize {
		t.Fatalf("key size = %d", len(key))
	}
}

func TestIssueTokenShape(t *testing.T) {
	now := time.Unix(testNow, 0)
	token, err := IssueToken(testSecret, "v1", `{"sub":"alice","n":7,"admin":true}`, "1h", now)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3: %q", len(parts), token)
	}
	for i, part := range parts {
		if strings.ContainsAny(part, "=+/") {
			t.Fatalf("segment %d is not unpadded base64url: %q", i, part)
		}
	}

	headerJSON := decodeSegment(t, parts[0])
	if want := `{"alg":"EdDSA","kid":"v1"}`; headerJSON != want {
		t.Fatalf("header = %s, want %s", headerJSON, want)
	}
	payloadJSON := decodeSegment(t, parts[1])
	if want := `{"admin":true,"exp":1700003600,"iat":1700000000,"n":7,"sub":"alice"}`; payloadJSON != want {
		t.Fatalf("payload = %s, want %s", payloadJSON, want)
	}

	key, err := DeriveKey(testSecret, "v1")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("signature is not base64url: %v", err)
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("signature does not verify against the derived public key")
	}
}

func TestIssueTokenClaimOverrides(t *testing.T) {
	now := time.Unix(testNow, 0)
	token, err := IssueToken(testSecret, "v1", `{"iat":1600000000,"exp":1600003600}`, "1h", now)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	claims, err := CheckToken(token, testSecret, time.Unix(1600000100, 0))
	if err != nil {
		t.Fatalf("CheckToken: %v", err)
	}
	if got := claims["iat"]; got != json.Number("1600000000") {
		t.Fatalf("iat = %v, want the caller value", got)
	}
	if got := claims["exp"]; got != json.Number("1600003600") {
		t.Fatalf("exp = %v, want the caller value", got)
	}
}

func TestIssueTokenWithoutTTLHasNoExp(t *testing.T) {
	token, err := IssueToken(testSecret, "v1", "", "", time.Unix(testNow, 0))
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	claims, err := CheckToken(token, testSecret, time.Unix(testNow, 0))
	if err != nil {
		t.Fatalf("CheckToken: %v", err)
	}
	if _, ok := claims["exp"]; ok {
		t.Fatal("exp was set without a ttl")
	}
}

func TestIssueTokenBadClaims(t *testing.T) {
	now := time.Unix(testNow, 0)
	for _, claims := range []string{`[1,2]`, `"str"`, `{`, `{"a":1}{"b":2}`} {
		if _, err := IssueToken(testSecret, "v1", claims, "", now); err == nil {
			t.Errorf("IssueToken accepted malformed claims %q", claims)
		}
	}
	if _, err := IssueToken(testSecret, "v1", `{"iat":"soon"}`, "1h", now); err == nil {
		t.Error("IssueToken accepted a non-numeric iat with a ttl")
	}
}

func TestIssueTokenBadTTL(t *testing.T) {
	if _, err := IssueToken(testSecret, "v1", "", "soon", time.Unix(testNow, 0)); err == nil {
		t.Fatal("IssueToken accepted an invalid ttl")
	}
}

func TestCheckTokenRoundTrip(t *testing.T) {
	now := time.Unix(testNow, 0)
	token, err := IssueToken(testSecret, "v1", `{"sub":"alice","nested":{"a":[1,2]}}`, "15m", now)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	claims, err := CheckToken(token, testSecret, now.Add(14*time.Minute))
	if err != nil {
		t.Fatalf("CheckToken: %v", err)
	}
	if got := claims["sub"]; got != "alice" {
		t.Fatalf("sub = %v", got)
	}
	nested, ok := claims["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested = %T, want object", claims["nested"])
	}
	list, ok := nested["a"].([]any)
	if !ok || len(list) != 2 {
		t.Fatalf("nested.a = %v", nested["a"])
	}
	if _, ok := claims["kid"]; ok {
		t.Fatal("claims must not be polluted with header fields")
	}
}

func TestCheckTokenRejectsBadInput(t *testing.T) {
	now := time.Unix(testNow, 0)
	token, err := IssueToken(testSecret, "v1", `{"sub":"alice"}`, "1h", now)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	parts := strings.Split(token, ".")

	algConfusion := strings.Replace(decodeSegment(t, parts[0]), "EdDSA", "HS256", 1)
	algTampered := base64.RawURLEncoding.EncodeToString([]byte(algConfusion))
	noKid := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))

	tests := []struct {
		name  string
		token string
		now   time.Time
		want  error
	}{
		{name: "empty", token: "", want: ErrInvalidToken},
		{name: "two segments", token: parts[0] + "." + parts[1], want: ErrInvalidToken},
		{name: "four segments", token: token + ".extra", want: ErrInvalidToken},
		{name: "empty segment", token: parts[0] + ".." + parts[2], want: ErrInvalidToken},
		{name: "alg confusion", token: algTampered + "." + parts[1] + "." + parts[2], want: ErrInvalidToken},
		{name: "missing kid", token: noKid + "." + parts[1] + "." + parts[2], want: ErrInvalidToken},
		{name: "tampered payload", token: parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"mallory","exp":1700003600,"iat":1700000000}`)) + "." + parts[2], want: ErrInvalidToken},
		{name: "truncated signature", token: parts[0] + "." + parts[1] + "." + parts[2][:10], want: ErrInvalidToken},
		{name: "expired", token: token, now: now.Add(time.Hour), want: ErrExpiredToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			when := now
			if !tt.now.IsZero() {
				when = tt.now
			}
			if _, err := CheckToken(tt.token, testSecret, when); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}

	if _, err := CheckToken(token, "another secret", now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("wrong secret error = %v", err)
	}
}

func TestCheckTokenValidatesTimes(t *testing.T) {
	now := time.Unix(testNow, 0)

	notYet := `{"iat":1700000000,"nbf":1700000600}`
	token, err := IssueToken(testSecret, "v1", notYet, "", now)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if _, err := CheckToken(token, testSecret, now.Add(5*time.Minute)); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("error = %v, want ErrNotYetValid", err)
	}
	if _, err := CheckToken(token, testSecret, now.Add(10*time.Minute)); err != nil {
		t.Fatalf("token should be valid at nbf: %v", err)
	}

	for _, claims := range []string{`{"exp":"never"}`, `{"nbf":[1]}`} {
		token, err := IssueToken(testSecret, "v1", claims, "", now)
		if err != nil {
			t.Fatalf("IssueToken(%s): %v", claims, err)
		}
		if _, err := CheckToken(token, testSecret, now); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("CheckToken(%s) error = %v, want ErrInvalidToken", claims, err)
		}
	}
}

func TestEmptySecretAndLabel(t *testing.T) {
	if _, err := DeriveKey("", "v1"); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("DeriveKey error = %v", err)
	}
	if _, err := DeriveKey(testSecret, ""); !errors.Is(err, ErrEmptyLabel) {
		t.Fatalf("DeriveKey error = %v", err)
	}
	if _, err := IssueToken("", "v1", "", "", time.Now()); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("IssueToken error = %v", err)
	}
	if _, err := IssueToken(testSecret, "", "", "", time.Now()); !errors.Is(err, ErrEmptyLabel) {
		t.Fatalf("IssueToken label error = %v", err)
	}
	if _, err := CheckToken("a.b.c", "", time.Now()); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("CheckToken error = %v", err)
	}
}

func decodeSegment(t *testing.T, segment string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("DecodeString(%q): %v", segment, err)
	}
	return string(raw)
}
