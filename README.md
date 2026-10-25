# Swarma witness

Canonical wire, signature, policy/transport and unserved transaction libraries for an append-only state-witness service.
The server is not served, deployed or qualified. Consumers remain in honest mode A until the
applicable witness and consumer activation gates close. This repository opens no
listener and provides no production append/latest, signer custody or recovery authority.
The [codec contract](spec/wire-v1.md) describes `wire`, `records` and `evidence`:
closed bindings/carriers, strict Keymaker record verification, bounded signed
receipt/head/control construction and proof-page checks. Signer callbacks are
supplied by callers; no production signer is implemented.
The [S2 policy contract](spec/policy-v1.md) adds protected role/consent/admin
validation and unserved transport predicates. G07 disclosure and G10 custody
gates stay closed with no configuration override. Record-key rotation remains unavailable.
The [S3 local contract](spec/storage-v1.md) adds immutable segments/journals,
one atomic root, original-receipt retry, a global audit chain and typed archive
interfaces. Its coordinator has no accepting production constructor. Independent
custodian/archive, time, exclusion, genesis/recovery and deployment qualification
remain closed. Synthetic providers live only in tests; injected file-call faults
prove ordering and refusal paths, never power-loss safety.

The conditional contract is the [witness-service specification](https://github.com/relux-works/swarma-keymaker/blob/7a2262ce2b8b84b9e9bc627972d4e07d62d34270/spec/witness-service.md),
with the separate [Keymaker consumer contract](https://github.com/relux-works/swarma-keymaker/blob/7a2262ce2b8b84b9e9bc627972d4e07d62d34270/spec/keymaker-witness.md).
The implementation will require exact LF-inclusive record acknowledgements,
compare-head append, challenge-bound authoritative latest reads, complete bounded
continuity proofs, independent durable custody and explicit role separation.
Unknown outcomes must retain evidence and fence; there is no weaker fallback.
Local codec and injected transaction checks establish only their documented scope;
none establishes a qualified serving instance.

Go 1.26.x is required. Strict crypto helpers use reviewed Waggle S5
`5f4e7435d75697385ff6ce15a7501ac6f31c8ea5`
(`v0.0.0-20261025015329-5f4e7435d756`). Its pinned registrar CCJ dependency
`v0.0.0-20261023164451-5f44ebf3f788` supplies canonical JSON directly.
The module policy allows only those exact versions. No verifier is copied and
no replacement directive is allowed. This aligns with K3's adopted spec and the
owner-registry module; K3's implementation module still pins S3 at the cited
contract revision. Freshness/journal adapters and checkpoint verification are
not activated by this dependency update. Registrar syntax/format checks cite the landed spec revision; they import no
registry package or Loader. Candidate-state truth and authenticated append
remain separate gates; no legacy format default is used.

## Tools

Run commands from a trusted, quiescent checkout. Go tools use the existing Go
build cache and standard temporary directory; supply private scratch when needed.
Ignored `.temp/` and `.tmp/` hold local evidence and are never publication inputs.
Keep private tracking, deny lists, operational logs and credentials outside the
published tree. Host scheduling policy is external to this portable Makefile.

| Tool | Purpose / exact entry point | Outputs and limits |
| --- | --- | --- |
| GitHub Actions | `.github/workflows/linux-ci.yml` runs on pull requests and pushes to main with Ubuntu 26.04 and Go 1.26.0: `go mod download`, `go mod verify`, `go mod tidy -diff`, `go build ./...`, `go vet ./...`, `bash -eo pipefail .github/scripts/check-format.sh`, `go run ./tools/hygiene -check`, `go run ./tools/vectors -check`, `go test -mod=readonly ./internal/deppolicy -count=1 -timeout=1m -v`, `python3 .github/scripts/check-hygiene.py`, `bash -eo pipefail .github/scripts/check-controls.sh`, `python3 .github/scripts/check-s3-controls.py`, `go test -mod=readonly ./... -count=1 -timeout=1m -v` | Actions logs and private temporary fixtures. Full checkout history is retained. The formatting gate preserves parser failures; isolated controls require stale-checksum, vet, formatting and four generic attribution refusals, including broken Windows-only syntax. Full tests have a one-minute per-package timeout and a ten-minute job limit; no privileged service qualification is claimed. |
| PENDING inventory | `bash -eo pipefail .github/scripts/report-pending.sh`; `bash -eo pipefail .github/scripts/check-pending-controls.sh` | CI discovers and lists documentation specifications from `pending-inventories.txt`, requires every `pending-rows.txt` lower-bound row, and refuses empty discovery. New specifications appear dynamically. Controls use isolated private fixtures; no qualification test bodies are executed or claimed passing. |
| Storage tests and mutation controls | `make test-storage`; `python3 .github/scripts/check-s3-controls.py` | Named transaction/codec checks and thirteen assertion-bound overlay mutations; private temporary files and console logs. [Coverage and PENDING qualification](spec/storage-tests.md). Bounded CAS/exact-retry race command is documented there. |
| Policy tests | `make test-policy` | Named narrow policy/config/transport checks; [pending dependencies](spec/policy-tests.md) remain explicit. |
| Wire tests | `make test-wire` | Console output; exact codec scope only. |
| Bootstrap tests | `make test` | Named bootstrap package tests, 30-second timeout; console output. Full suites belong to review. |
| Vet | `make vet` | Bootstrap/tool diagnostics on console. |
| Go build | `make build` | Compiles libraries and the two commands to the Go build cache; no server binary or repository output. |
| Module verification | `make mod-verify` | Verifies installed module cache entries; exact Waggle and registrar dependency pins. |
| Formatting | `make format` | Lists files needing gofmt on console; empty output is the expected result. |
| Publication hygiene | `make hygiene` or `go run ./tools/hygiene -check` | Nonzero on bounded private-artifact/key-marker/local-path/identity/tracking/link checks or dependency policy failure. Reports categories and safe relative paths, not matching content. |
| Private deny list | `go run ./tools/hygiene -check -deny-file <private-list>` | Optional bounded newline-separated forbidden values, held outside the tree; values are not printed. |
| Vector integrity | `make vectors` or `go run ./tools/vectors -check` | Checks the exact manifest and declared bytes; checks the frozen first-party fixtures; semantic codec tests consume those same bytes. |
| Consumer lock check | `go run ./tools/vectors -check -root <corpus-checkout> -lock <consumer-lock.json>` | Offline exact commit/digest/data check; no network or code import. See the [data contract](testdata/witness-v1/README.md). |

Hygiene excludes `.git` internals and ignored scratch directories. It refuses a
private tracking directory even if ignored. It is a bounded aid, not universal
secret detection or authorization to publish. Supply private deny entries for
organization-specific names and identifiers and review the staged diff manually.
Synthetic tests demonstrate specific detections; they do not prove absence of
unknown secrets. Tools assume the checkout is not being concurrently modified.

Tests cover forbidden publication material, link refusal, changed/missing/extra
vector bytes, ambiguous metadata, checkout/digest lock mismatches and unapproved
module requirements. Each has valid controls. Service protocol and lifecycle
coverage remain pending, including service-level WS01–WS19 qualification. Codec
tests cover specific byte/signature properties only. The bounded
mutation controls below remove one guard in an isolated source overlay; each
must fail its named test at the rejection assertion, rather than fail to build.
They establish specific checker coverage, not universal detection.

| Mutant | Removed guard | Named regression test |
| --- | --- | --- |
| M00_IGNORE_PRIVATE_PATH | Private tracking path refusal | TestHygieneRejectsPrivateArtifacts |
| M00_SKIP_FIXTURE_DIGEST | Fixture content digest (size retained) | TestVectorManifestRejectsMissingOrChangedBytes/same-size |
| M00_ALLOW_UNPINNED_DEPENDENCY | Exact approved dependency version | TestDependencyPolicyRejectsUnapprovedModule |
| M00_SKIP_LOCK_COMMIT | Lock-to-checkout commit equality | TestVectorLockRejectsWrongIdentity/commit |
| M00_ECHO_PRIVATE_NAME | Filename redaction | TestHygieneRedactsPrivateNames |
| M00_ALLOW_CASED_METADATA | Exact member names and non-null values | TestVectorMetadataRequiresExactFields |

The public license, control-metadata disclosure consent and independent custodian
provider/SLA remain open. See [unresolved questions](UNRESOLVED_QUESTIONS.md).

The S1 negative-first tests and six narrowing controls are documented in the
[codec checks](spec/wire-tests.md). Frozen [first-party data](testdata/witness-v1/README.md)
contains no third-party fixtures. Authenticated registrar append, checkpoint verification,
production transport authorization, qualified storage/recovery and serving remain unavailable.
