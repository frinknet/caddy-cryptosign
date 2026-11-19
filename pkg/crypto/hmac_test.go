package crypto

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignHMAC(t *testing.T) {
	got, err := SignHMAC("secret", "hello")
	if err != nil {
		t.Fatalf("SignHMAC: %v", err)
	}
	if want := "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"; got != want {
		t.Fatalf("SignHMAC = %s, want %s", got, want)
	}

	if _, err := SignHMAC("", "hello"); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("empty secret error = %v", err)
	}
}

func TestSignHMACExactBytes(t *testing.T) {
	// Whitespace, case, and JSON field order are all part of the message.
	a, _ := SignHMAC("k", `{"b":2,"a":1}`)
	b, _ := SignHMAC("k", `{"a":1,"b":2}`)
	c, _ := SignHMAC("k", ` {"b":2,"a":1}`)
	if a == b || a == c {
		t.Fatal("different byte sequences produced the same digest")
	}
}

func TestCheckHMACPlain(t *testing.T) {
	payload := `{"event":"paid"}`
	digest, err := SignHMAC("s3cr3t", payload)
	if err != nil {
		t.Fatalf("SignHMAC: %v", err)
	}

	result, err := CheckHMAC("s3cr3t", payload, digest, 0, time.Now())
	if err != nil {
		t.Fatalf("CheckHMAC: %v", err)
	}
	if got := result["payload"]; got != payload {
		t.Fatalf("payload = %v", got)
	}
	if _, ok := result["timestamp"]; ok {
		t.Fatal("plain digest must not report a timestamp")
	}

	if _, err := CheckHMAC("s3cr3t", payload+" ", digest, 0, time.Now()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered payload error = %v", err)
	}
	if _, err := CheckHMAC("wrong", payload, digest, 0, time.Now()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong secret error = %v", err)
	}
	if _, err := CheckHMAC("s3cr3t", payload, "zzzz", 0, time.Now()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("non-hex signature error = %v", err)
	}
	if _, err := CheckHMAC("s3cr3t", payload, "", 0, time.Now()); !errors.Is(err, ErrEmptySignature) {
		t.Fatalf("empty signature error = %v", err)
	}
	if _, err := CheckHMAC("", payload, digest, 0, time.Now()); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("empty secret error = %v", err)
	}
}

func TestCheckHMACRotation(t *testing.T) {
	payload := "body"
	digest, err := SignHMAC("s3cr3t", payload)
	if err != nil {
		t.Fatalf("SignHMAC: %v", err)
	}

	upper := strings.ToUpper(digest)
	if _, err := CheckHMAC("s3cr3t", payload, upper, 0, time.Now()); err != nil {
		t.Fatalf("uppercase hex: %v", err)
	}
	if _, err := CheckHMAC("s3cr3t", payload, "00ff,"+digest, 0, time.Now()); err != nil {
		t.Fatalf("comma-separated candidates: %v", err)
	}
	if _, err := CheckHMAC("s3cr3t", payload, "00ff,deadbeef", 0, time.Now()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("error = %v", err)
	}
}

func TestCheckHMACStripeStyle(t *testing.T) {
	const (
		payload = `{"id":"evt_1"}`
		ts      = int64(1700000000)
	)
	digest, err := SignHMAC("s3cr3t", "1700000000."+payload)
	if err != nil {
		t.Fatalf("SignHMAC: %v", err)
	}
	header := "t=1700000000,v1=" + digest

	result, err := CheckHMAC("s3cr3t", payload, header, 5*time.Minute, time.Unix(ts+120, 0))
	if err != nil {
		t.Fatalf("CheckHMAC: %v", err)
	}
	if got := result["timestamp"]; got != ts {
		t.Fatalf("timestamp = %v (%T)", got, got)
	}

	if _, err := CheckHMAC("s3cr3t", payload, header, 60*time.Second, time.Unix(ts+120, 0)); !errors.Is(err, ErrTimestampOutOfTolerance) {
		t.Fatalf("stale timestamp error = %v", err)
	}
	if _, err := CheckHMAC("s3cr3t", payload, header, time.Minute, time.Unix(ts-120, 0)); !errors.Is(err, ErrTimestampOutOfTolerance) {
		t.Fatalf("future timestamp error = %v", err)
	}
	if _, err := CheckHMAC("s3cr3t", payload, header, -time.Second, time.Unix(ts, 0)); err == nil {
		t.Fatal("negative tolerance accepted")
	}

	// Timestamp is part of the signed string, so moving it breaks the digest.
	moved := "t=1700000100,v1=" + digest
	if _, err := CheckHMAC("s3cr3t", payload, moved, 0, time.Unix(ts, 0)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("moved timestamp error = %v", err)
	}

	// Extra v1 entries are accepted for rotation.
	rotated := "t=1700000000,v1=deadbeef,v1=" + digest
	if _, err := CheckHMAC("s3cr3t", payload, rotated, 0, time.Unix(ts, 0)); err != nil {
		t.Fatalf("rotation: %v", err)
	}
}

func TestCheckHMACStripeMalformed(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{name: "no timestamp", header: "v1=deadbeef"},
		{name: "no digest", header: "t=1700000000"},
		{name: "bad timestamp", header: "t=soon,v1=deadbeef"},
		{name: "negative timestamp", header: "t=-1,v1=deadbeef"},
		{name: "junk part", header: "t=1700000000,junk"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := CheckHMAC("s3cr3t", "body", tt.header, 0, time.Now()); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("error = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

func TestCheckHMACToleranceNeedsTimestamp(t *testing.T) {
	digest, err := SignHMAC("s3cr3t", "body")
	if err != nil {
		t.Fatalf("SignHMAC: %v", err)
	}
	if _, err := CheckHMAC("s3cr3t", "body", digest, time.Minute, time.Now()); err == nil {
		t.Fatal("tolerance with a bare digest was accepted")
	}
}

func TestCheckHMACSubSecondTolerance(t *testing.T) {
	const (
		payload = "body"
		ts      = int64(1700000000)
	)
	digest, err := SignHMAC("s3cr3t", "1700000000."+payload)
	if err != nil {
		t.Fatalf("SignHMAC: %v", err)
	}
	header := "t=1700000000,v1=" + digest
	now := time.Unix(ts, 0).Add(500 * time.Millisecond)

	if _, err := CheckHMAC("s3cr3t", payload, header, 500*time.Millisecond, now); err != nil {
		t.Fatalf("500ms offset with a 500ms tolerance: %v", err)
	}
	if _, err := CheckHMAC("s3cr3t", payload, header, 250*time.Millisecond, now); !errors.Is(err, ErrTimestampOutOfTolerance) {
		t.Fatalf("250ms tolerance error = %v, want ErrTimestampOutOfTolerance", err)
	}
	if _, err := CheckHMAC("s3cr3t", payload, header, 500*time.Microsecond, now); !errors.Is(err, ErrTimestampOutOfTolerance) {
		t.Fatalf("microsecond tolerance error = %v, want ErrTimestampOutOfTolerance", err)
	}
}
