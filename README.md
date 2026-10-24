# Swarma witness

Repository bootstrap for an append-only state-witness service. The server is not
implemented, deployed or qualified. Consumers remain in honest mode A until the
applicable witness and consumer activation gates close. This repository opens no
listener and provides no append, receipt, head, signing or recovery authority.

The conditional contract is the [witness-service specification](https://github.com/relux-works/swarma-keymaker/blob/0ae0c4e93c3fae9db2bcadcfb5eeafbdcf0668c0/spec/witness-service.md),
with the separate [Keymaker consumer contract](https://github.com/relux-works/swarma-keymaker/blob/0ae0c4e93c3fae9db2bcadcfb5eeafbdcf0668c0/spec/keymaker-witness.md).
The implementation will require exact LF-inclusive record acknowledgements,
compare-head append, challenge-bound authoritative latest reads, complete bounded
continuity proofs, independent durable custody and explicit role separation.
Unknown outcomes must retain evidence and fence; there is no weaker fallback.
None of those service properties is implemented by these bootstrap tools.

Go 1.26.x is required. The module currently uses only the standard library.
Permitted future dependencies are the reviewed Waggle S3 commit
`9b42338b8a57d12a21da4db4375b269deacdd6bf` and an explicitly reviewed Keymaker pin
when needed. The current module-policy check allows only the exact Waggle
pseudo-version for that commit; adding a required Keymaker pin is a separate
explicit policy change. No verifier code is copied. S4 is not pinned or enabled.
Unused dependencies are not installed; there is no go.sum without dependencies.

## Tools

Run commands from a trusted, quiescent checkout. Go tools use the existing Go
build cache and standard temporary directory; supply private scratch when needed.
Ignored `.temp/` and `.tmp/` hold local evidence and are never publication inputs.
Keep private tracking, deny lists, operational logs and credentials outside the
published tree. Host scheduling policy is external to this portable Makefile.

| Tool | Purpose / exact entry point | Outputs and limits |
| --- | --- | --- |
| Narrow tests | `make test` | Named bootstrap package tests, 30-second timeout; console output. Full suites belong to review. |
| Vet | `make vet` | Bootstrap/tool diagnostics on console. |
| Go build | `make build` | Compiles the two commands to the Go build cache; no server binary or repository output. |
| Module verification | `make mod-verify` | Verifies installed module cache entries; currently no dependencies. |
| Formatting | `make format` | Lists files needing gofmt on console; empty output is the expected result. |
| Publication hygiene | `make hygiene` or `go run ./tools/hygiene -check` | Nonzero on bounded private-artifact/key-marker/local-path/identity/tracking/link checks or dependency policy failure. Reports categories and safe relative paths, not matching content. |
| Private deny list | `go run ./tools/hygiene -check -deny-file <private-list>` | Optional bounded newline-separated forbidden values, held outside the tree; values are not printed. |
| Vector integrity | `make vectors` or `go run ./tools/vectors -check` | Checks the exact manifest and declared bytes; reports zero vectors and PENDING conformance at bootstrap. |
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
coverage remain pending, including all normative WS01–WS19 rows. The bounded
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
