// Package cryptosign registers the crypto template functions with Caddy.
// The implementation lives in pkg/tplfuncs and pkg/crypto; importing this
// package is what makes the http.handlers.templates.functions.crypto
// extension module available to the templates handler.
package cryptosign

import (
	_ "github.com/frinknet/caddy-cryptosign/pkg/tplfuncs"
)
