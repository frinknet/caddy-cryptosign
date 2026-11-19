// Package rawbody captures the request body before any other handler consumes,
// parses, or rewrites it, and exposes the exact bytes to templates through a
// request variable. Webhook verification needs those bytes verbatim: decoding
// and re-marshaling JSON changes key order and whitespace.
package rawbody

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// DefaultMaxSize is the body size limit used when none is configured.
const DefaultMaxSize int64 = 1 << 20

// VarName is the request variable holding the captured body. Templates read
// it with {{ placeholder "http.vars.cryptobody" }}.
const VarName = "cryptobody"

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("cryptobody", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("cryptobody", httpcaddyfile.Before, "templates")
}

// Handler is the cryptobody middleware.
type Handler struct {
	// MaxSize caps the captured body in bytes. Bodies larger than this are
	// rejected with 413 rather than silently truncated.
	MaxSize int64 `json:"max_size,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cryptobody",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision fills in the default body limit.
func (h *Handler) Provision(caddy.Context) error {
	if h.MaxSize < 0 {
		return fmt.Errorf("cryptobody: max_size must not be negative")
	}
	if h.MaxSize == 0 {
		h.MaxSize = DefaultMaxSize
	}
	return nil
}

// ServeHTTP reads the body, restores it for downstream handlers, and stores it
// in the request variable table.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	body, err := h.capture(r)
	if err != nil {
		return err
	}
	caddyhttp.SetVar(r.Context(), VarName, body)
	return next.ServeHTTP(w, r)
}

func (h Handler) capture(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}

	limit := h.MaxSize
	if limit <= 0 {
		limit = DefaultMaxSize
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return "", caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("cryptobody: reading request body: %w", err))
	}
	_ = r.Body.Close()
	// Downstream handlers still get the bytes they expected.
	r.Body = io.NopCloser(bytes.NewReader(raw))

	if int64(len(raw)) > limit {
		return "", caddyhttp.Error(http.StatusRequestEntityTooLarge, fmt.Errorf("cryptobody: request body exceeds %d bytes", limit))
	}
	return string(raw), nil
}

// UnmarshalCaddyfile accepts:
//
//	cryptobody [<max_size>]
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	if d.NextArg() {
		size := d.Val()
		n, err := strconv.ParseInt(size, 10, 64)
		if err != nil || n <= 0 {
			return d.Errf("cryptobody: max size %q must be a positive integer", size)
		}
		h.MaxSize = n
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	if d.NextBlock(d.Nesting()) {
		return d.Err("cryptobody takes no block")
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

var (
	_ caddy.Module                = Handler{}
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
