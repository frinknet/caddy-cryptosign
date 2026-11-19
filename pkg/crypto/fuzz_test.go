package crypto

import (
	"testing"
	"time"
)

func FuzzCheckToken(f *testing.F) {
	fixed := time.Unix(testNow, 0)
	valid, err := IssueToken(testSecret, "v1", `{"sub":"alice"}`, "1h", fixed)
	if err != nil {
		f.Fatalf("IssueToken: %v", err)
	}
	for _, seed := range []string{valid, "", "a.b.c", "..", "eyJhbGciOiJFZERTQSJ9.e30.AAAA"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, token string) {
		claims, err := CheckToken(token, testSecret, fixed)
		if err == nil && claims == nil {
			t.Fatal("successful verification returned nil claims")
		}
	})
}

func FuzzParseSignatureHeader(f *testing.F) {
	for _, seed := range []string{
		"t=1700000000,v1=deadbeef",
		"t=0,v1=",
		"v1=deadbeef",
		"t=soon,v1=deadbeef",
		"=,=,=",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, header string) {
		ts, sigs, err := parseSignatureHeader(header)
		if err != nil {
			return
		}
		if ts < 0 {
			t.Fatalf("accepted a negative timestamp %d", ts)
		}
		if len(sigs) == 0 {
			t.Fatal("accepted a header with no digests")
		}
		for _, sig := range sigs {
			if sig == "" {
				t.Fatal("accepted an empty digest")
			}
		}
	})
}
