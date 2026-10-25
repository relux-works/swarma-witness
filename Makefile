GO ?= go

.PHONY: test test-time test-wire test-policy test-storage vet build hygiene vectors format mod-verify

# Only the bootstrap packages are exercised here. Full suites belong to review.
test:
	$(GO) test ./internal/hygiene ./internal/vectors ./internal/deppolicy ./tools/hygiene ./tools/vectors -count=1 -timeout=30s

test-time:
	$(GO) test -mod=readonly ./internal/qualifiedtime ./internal/deppolicy -count=1 -timeout=3m
	$(GO) test -mod=readonly -tags=swarma_timeconf_fixture ./internal/qualifiedtime -count=1 -timeout=1m

test-wire:
	$(GO) test ./wire ./records ./evidence -run 'Test(Wire|Record|Records|Evidence)' -count=1 -timeout=60s

test-policy:
	$(GO) test ./policy ./config ./transport -run 'Test(ACL|Provision|Admin|Rotation|TLS)' -count=1 -timeout=60s

test-storage:
	$(GO) test ./store ./audit ./archive ./service -run 'Test(CAS|Occupied|Prepared|AdminActivation|AuditFailure|Storage|AuditClosed|AuditReaders|Archive|ServiceDependencies|Reviewer)' -count=1 -timeout=90s

vet:
	$(GO) vet ./internal/hygiene ./internal/vectors ./internal/deppolicy ./tools/hygiene ./tools/vectors

build:
	$(GO) build ./wire ./records ./evidence ./policy ./config ./transport ./store ./audit ./archive ./custodian ./service ./tools/hygiene ./tools/vectors

hygiene:
	$(GO) run ./tools/hygiene -check

vectors:
	$(GO) run ./tools/vectors -check

format:
	gofmt -l internal tools wire records evidence policy config transport store audit archive custodian service

mod-verify:
	$(GO) mod verify
