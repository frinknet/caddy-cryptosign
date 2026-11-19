package rawbody

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func newRequest(t *testing.T, body io.Reader) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://example.test/hook", body)
	vars := make(map[string]any)
	return r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars))
}

func runHandler(t *testing.T, h Handler, r *http.Request) (*http.Request, error) {
	t.Helper()
	var seen *http.Request
	err := h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, rr *http.Request) error {
		seen = rr
		return nil
	}))
	return seen, err
}

func TestCapturesExactBytes(t *testing.T) {
	const body = "{\n  \"b\": 2,  \"a\": 1\n}\x00trailing"
	r := newRequest(t, strings.NewReader(body))
	h := Handler{MaxSize: 1024}

	next, err := runHandler(t, h, r)
	if err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if got := caddyhttp.GetVar(r.Context(), VarName); got != body {
		t.Fatalf("var = %q, want %q", got, body)
	}
	if next == nil {
		t.Fatal("next handler was not called")
	}
	restored, err := io.ReadAll(next.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(restored) != body {
		t.Fatalf("restored body = %q, want %q", restored, body)
	}
}

func TestEmptyAndNilBody(t *testing.T) {
	h := Handler{MaxSize: 16}

	r := newRequest(t, strings.NewReader(""))
	if _, err := runHandler(t, h, r); err != nil {
		t.Fatalf("empty body: %v", err)
	}
	if got := caddyhttp.GetVar(r.Context(), VarName); got != "" {
		t.Fatalf("empty body var = %v", got)
	}

	r = newRequest(t, nil)
	r.Body = nil
	if _, err := runHandler(t, h, r); err != nil {
		t.Fatalf("nil body: %v", err)
	}
	if got := caddyhttp.GetVar(r.Context(), VarName); got != "" {
		t.Fatalf("nil body var = %v", got)
	}
}

func TestOverLimitIsRejected(t *testing.T) {
	h := Handler{MaxSize: 4}
	nextCalled := false
	err := h.ServeHTTP(httptest.NewRecorder(), newRequest(t, strings.NewReader("12345")),
		caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			nextCalled = true
			return nil
		}))
	if nextCalled {
		t.Fatal("next handler ran for an oversized body")
	}
	var herr caddyhttp.HandlerError
	if !errors.As(err, &herr) || herr.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("error = %v, want 413", err)
	}
}

func TestBoundarySizedBodyIsAccepted(t *testing.T) {
	h := Handler{MaxSize: 5}
	if _, err := runHandler(t, h, newRequest(t, strings.NewReader("12345"))); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
}

func TestProvisionDefault(t *testing.T) {
	h := Handler{}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if h.MaxSize != DefaultMaxSize {
		t.Fatalf("MaxSize = %d, want %d", h.MaxSize, DefaultMaxSize)
	}
	if err := (&Handler{MaxSize: -1}).Provision(caddy.Context{}); err == nil {
		t.Fatal("negative max size accepted")
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{input: "cryptobody"},
		{input: "cryptobody 65536", want: 65536},
		{input: "cryptobody 0", wantErr: true},
		{input: "cryptobody -1", wantErr: true},
		{input: "cryptobody soon", wantErr: true},
		{input: "cryptobody 1 2", wantErr: true},
		{input: "cryptobody {\n\tx\n}", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var h Handler
			err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalCaddyfile: %v", err)
			}
			if h.MaxSize != tt.want {
				t.Fatalf("MaxSize = %d, want %d", h.MaxSize, tt.want)
			}
		})
	}
}
