package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignHMAC returns the lowercase hexadecimal HMAC-SHA256 of payload keyed with
// secret. The payload is signed exactly as given: no trimming, re-encoding, or
// timestamp injection.
func SignHMAC(secret, payload string) (string, error) {
	if secret == "" {
		return "", ErrEmptySecret
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// CheckHMAC verifies a body/webhook signature.
//
// sigHeader is either a bare hexadecimal HMAC (comma-separated values are
// accepted for key rotation) over payload, or a Stripe-style header such as
// "t=1700000000,v1=<hex>" in which case the signed string is
// "<timestamp>.<payload>". When a timestamp is present and tolerance is
// positive, the timestamp must be within tolerance of now; the comparison is
// exact, so sub-second tolerances are honored.
//
// On success the returned map holds "payload" and, for Stripe-style headers,
// "timestamp" as an int64.
func CheckHMAC(secret, payload, sigHeader string, tolerance time.Duration, now time.Time) (map[string]any, error) {
	if secret == "" {
		return nil, ErrEmptySecret
	}
	if sigHeader == "" {
		return nil, ErrEmptySignature
	}
	if tolerance < 0 {
		return nil, fmt.Errorf("cryptosign: tolerance must not be negative")
	}

	signed := payload
	candidates := []string{}
	var (
		timestamp    int64
		hasTimestamp bool
	)

	if hasSignatureKeys(sigHeader) {
		ts, sigs, err := parseSignatureHeader(sigHeader)
		if err != nil {
			return nil, err
		}
		timestamp, hasTimestamp = ts, true
		candidates = sigs
		signed = strconv.FormatInt(ts, 10) + "." + payload

		if tolerance > 0 {
			delta := now.Sub(time.Unix(ts, 0))
			if delta < 0 {
				delta = -delta
			}
			if delta > tolerance {
				return nil, ErrTimestampOutOfTolerance
			}
		}
	} else {
		if tolerance > 0 {
			return nil, fmt.Errorf("cryptosign: tolerance requires a t=<unix> signature header")
		}
		for _, part := range strings.Split(sigHeader, ",") {
			if part = strings.TrimSpace(part); part != "" {
				candidates = append(candidates, part)
			}
		}
		if len(candidates) == 0 {
			return nil, ErrEmptySignature
		}
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	expected := mac.Sum(nil)

	matched := false
	for _, candidate := range candidates {
		raw, err := hex.DecodeString(candidate)
		if err != nil {
			continue
		}
		if hmac.Equal(expected, raw) {
			matched = true
		}
	}
	if !matched {
		return nil, ErrInvalidSignature
	}

	result := map[string]any{"payload": payload}
	if hasTimestamp {
		result["timestamp"] = timestamp
	}
	return result, nil
}

// hasSignatureKeys reports whether the header uses key=value pairs rather than
// a bare digest. Stripe-style headers always carry an explicit "t".
func hasSignatureKeys(header string) bool {
	for _, part := range strings.Split(header, ",") {
		key, _, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && (key == "t" || key == "v1") {
			return true
		}
	}
	return false
}

func parseSignatureHeader(header string) (int64, []string, error) {
	var (
		tsRaw string
		sigs  []string
	)
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return 0, nil, fmt.Errorf("%w: malformed signature header", ErrInvalidSignature)
		}
		switch key {
		case "t":
			tsRaw = value
		case "v1":
			if value != "" {
				sigs = append(sigs, value)
			}
		}
	}

	if tsRaw == "" {
		return 0, nil, fmt.Errorf("%w: signature header has no timestamp", ErrInvalidSignature)
	}
	if len(sigs) == 0 {
		return 0, nil, fmt.Errorf("%w: signature header has no v1 digest", ErrInvalidSignature)
	}
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil || ts < 0 {
		return 0, nil, fmt.Errorf("%w: timestamp %q is not a Unix time", ErrInvalidSignature, tsRaw)
	}
	return ts, sigs, nil
}
