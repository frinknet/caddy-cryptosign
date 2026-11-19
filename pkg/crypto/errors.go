// Package crypto implements the primitives behind the cryptotoken,
// cryptosign, and cryptocheck template functions.
//
// Tokens are compact EdDSA JWTs whose Ed25519 keypair is derived from a
// caller-supplied secret and key label with HKDF-SHA256. Body signatures
// are plain HMAC-SHA256 digests rendered as lowercase hexadecimal.
package crypto

import "errors"

var (
	// ErrEmptySecret is returned whenever a caller passes a zero-length secret.
	ErrEmptySecret = errors.New("cryptosign: secret must not be empty")
	// ErrEmptyLabel is returned when a key derivation label is missing.
	ErrEmptyLabel = errors.New("cryptosign: key label must not be empty")
	// ErrInvalidToken covers malformed, unsigned, or otherwise unusable JWTs.
	ErrInvalidToken = errors.New("cryptosign: invalid token")
	// ErrExpiredToken is returned when exp is at or before the current time.
	ErrExpiredToken = errors.New("cryptosign: token expired")
	// ErrNotYetValid is returned when nbf is after the current time.
	ErrNotYetValid = errors.New("cryptosign: token not yet valid")
	// ErrInvalidSignature covers every body-signature mismatch.
	ErrInvalidSignature = errors.New("cryptosign: invalid signature")
	// ErrTimestampOutOfTolerance is returned when a webhook timestamp falls
	// outside the caller's tolerance window.
	ErrTimestampOutOfTolerance = errors.New("cryptosign: timestamp outside tolerance")
	// ErrEmptySignature is returned when no signature header was supplied.
	ErrEmptySignature = errors.New("cryptosign: signature must not be empty")
)
