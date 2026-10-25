GO ?= go

.PHONY: test test-wire test-policy vet build hygiene vectors format mod-verify

# Only the bootstrap packages are exercised here. Full suites belong to review.
test:
	$(GO) test ./internal/hygiene ./internal/vectors ./internal/deppolicy ./tools/hygiene ./tools/vectors -count=1 -timeout=30s

test-wire:
	$(GO) test ./wire ./records ./evidence -run 'Test(Wire|Record|Records|Evidence)' -count=1 -timeout=60s

test-policy:
	$(GO) test ./policy ./config ./transport -run 'Test(ACL|Provision|Admin|Rotation|TLS)' -count=1 -timeout=60s

vet:
	$(GO) vet ./internal/hygiene ./internal/vectors ./internal/deppolicy ./tools/hygiene ./tools/vectors

build:
	$(GO) build ./wire ./records ./evidence ./policy ./config ./transport ./tools/hygiene ./tools/vectors

hygiene:
	$(GO) run ./tools/hygiene -check

vectors:
	$(GO) run ./tools/vectors -check

format:
	gofmt -l internal tools wire records evidence policy config transport

mod-verify:
	$(GO) mod verify
