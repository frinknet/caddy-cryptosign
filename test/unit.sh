#!/bin/sh

# Format, vet, test, then repeat the tests under the race detector. The race
# detector needs cgo, so the builder image gets a compiler installed inside the
# disposable container; the host still needs no Go toolchain.
timeout 280 docker run --rm \
  -v caddy-sf-mod:/mod \
  -v "$PWD":/src \
  -w /src \
  -e GOMODCACHE=/mod \
  -e GOCACHE=/mod/gocache \
  caddy:2.11.9-builder-alpine \
  sh -c 'set -e
    test -z "$(gofmt -l .)"
    CGO_ENABLED=0 go vet ./...
    CGO_ENABLED=0 go test -timeout=120s ./...
    apk add --no-cache gcc musl-dev >/dev/null
    CGO_ENABLED=1 go test -race -timeout=180s ./...'
