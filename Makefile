GO ?= go

.PHONY: test vet build hygiene vectors format mod-verify

# Only the bootstrap packages are exercised here. Full suites belong to review.
test:
	$(GO) test ./internal/hygiene ./internal/vectors ./internal/deppolicy ./tools/hygiene ./tools/vectors -count=1 -timeout=30s

vet:
	$(GO) vet ./internal/hygiene ./internal/vectors ./internal/deppolicy ./tools/hygiene ./tools/vectors

build:
	$(GO) build ./tools/hygiene ./tools/vectors

hygiene:
	$(GO) run ./tools/hygiene -check

vectors:
	$(GO) run ./tools/vectors -check

format:
	gofmt -l internal tools

mod-verify:
	$(GO) mod verify
