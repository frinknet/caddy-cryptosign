// Package cryptosign registers the crypto template functions and the raw body
// handler with Caddy. The implementation lives in pkg/tplfuncs, pkg/crypto, and
// pkg/rawbody; importing this package is what makes the
// http.handlers.templates.functions.crypto extension module and the
// http.handlers.cryptobody handler available in an xcaddy build.
package cryptosign

import (
	_ "github.com/frinknet/caddy-cryptosign/pkg/rawbody"
	_ "github.com/frinknet/caddy-cryptosign/pkg/tplfuncs"
)
