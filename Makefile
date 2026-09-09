BINARY   := mellon
MODULE   := github.com/skybert/mellon
BUILDDIR := build
DISTDIR  := dist
GOFLAGS  :=
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

all: fmt lint test vulncheck build man

build: fmt
	mkdir -p $(BUILDDIR)
	go build $(GOFLAGS) -ldflags "-X main.Version=$(VERSION)" -o $(BUILDDIR)/$(BINARY) .

run: build
	./$(BUILDDIR)/$(BINARY)

mtls/server:
	go run mtls/server.go

mtls/client:
	go run mtls/client/client.go

certs:
	./bin/create-certs

test:
	go test ./...

lint:
	golangci-lint run ./...

vuln:
	govulncheck ./...

fmt:
	gofmt -w -s .

clean:
	rm -rf $(BUILDDIR) $(DISTDIR)

upgrade:
	go get -u
	go mod tidy

install: build
	mkdir -p ~/.local/bin
	cp $(BUILDDIR)/$(BINARY) ~/.local/bin/$(BINARY)

# Used by CI/CD to build release binaries. GOOS and GOARCH env vars
# are set in the CI/CD conf.
dist:
	@mkdir -p $(DISTDIR)
	CGO_ENABLED=0 go build -ldflags "-X main.Version=$(VERSION)" -o dist/$(BINARY)-$(VERSION)-${GOOS}-${GOARCH} .

.PHONY: all build certs test lint vulncheck fmt clean install man dist upgrade mtls/client mtls/server
