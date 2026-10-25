# WC1 inactive adapter checks

`go test -mod=readonly ./internal/qualifiedtime ./internal/deppolicy -count=1 -timeout=3m -v`
checks closed production factories, structural terminal call restrictions, the
one-entry mapping, and fixture dependency containment. The dependency scan visits
every Go file except `.git`, including scratch/dot/underscore and platform-excluded
files; the fixture tag must be logically necessary on `_test.go` imports. Real
non-test graphs are checked both with and without the fixture tag. Valid controls
and compiling import/construction plants exercise those instruments.

`go test -mod=readonly -tags=swarma_timeconf_fixture ./internal/qualifiedtime -count=1 -timeout=1m -v`
uses only tagged test-file imports of broker `timeconftest`. Exact private
preparations and local S3 files are real; clock/epoch/endpoint enforcement is a
synthetic model. Use a private 0700 TMPDIR with protected ancestors (a root-owned
sticky `/tmp` is supported). This executes no native time provider or server.
`go test -mod=readonly ./store -run '^TestTimeUse' -count=1 -timeout=30s -v`
checks local metadata monotonicity, barrier faults and retained owning roots;
its synthetic storage-codec data is not authenticated time evidence.

| Window | Native binding and adapter | Named checks | Narrowing mutants |
| --- | --- | --- | --- |
| P | Read set inside native operation plus retained exact snapshot; PAdapter | TestWindowTimelyEndpoint, TestWindowStaleAndPostReadPause, TestWindowDoubleCheckAndExtraRead, TestWindowNativeReadSetAndEpoch, TestWindowStableKey, TestWindowOriginalsAndBinding, TestWindowTransitionMapping | G16_CAPTURE_BEFORE_ADMISSION, G16_SECOND_READ, G16_BURN_AFTER_ACT, G16_H_AS_KEY, G16_EPOCH_EQUALS_RUN |
| R | Read set inside native operation plus retained exact snapshot; RAdapter | Same named parameterized checks with R subcases | Same five mutants plus G16_LATE_AUTHORITY_COMMIT |
| X | Read set inside native operation plus retained exact snapshot; XAdapter | Same named X subcases; TestXPostSendAccountingFailure, TestWindowLateCommitForbidden, TestWindowPostCommitPause | Same five plus G16_X_SEND_BEFORE_COMMIT, G16_LATE_AUTHORITY_COMMIT |
| TLS | Unchanged native TLS digest; separately retained/compared snapshot before m; TLSAdapter | Same named TLS subcases, including equality with transport.ConsumerOperationDigest; TestWindowLateCommitForbidden, TestWindowPostCommitPause | Same five mutants plus G16_LATE_AUTHORITY_COMMIT |

`python3 .github/scripts/check-g16-controls.py` runs the unchanged tagged control,
then ten private source overlays. Each must exit 1 at its named test assertion;
setup/build failures, timeouts and missing assertions are survivors. No source
checkout, module cache or production dependency is modified by those controls.

| Mutant | Narrows the gate to / removed property | Named failing test |
| --- | --- | --- |
| G16_CAPTURE_BEFORE_ADMISSION | Capture before the final gate/admission, denying the valid complete trace | TestWindowTimelyEndpoint |
| G16_SECOND_READ | A second capture attempt, denying the valid single-read trace | TestWindowTimelyEndpoint |
| G16_BURN_AFTER_ACT | Endpoint attempted with unused durable state | TestWindowTimelyEndpoint |
| G16_X_SEND_BEFORE_COMMIT | Send attempted on burn alone | TestXPostSendAccountingFailure |
| G16_LATE_AUTHORITY_COMMIT | Full-endpoint enforcement bypassed, allowing a late authority commit | TestWindowLateCommitForbidden |
| G16_H_AS_KEY | H-derived key replaces the authorized original slot, denying its valid control | TestWindowStableKey |
| G16_EPOCH_EQUALS_RUN | Live writer epoch replaced by a per-attempt run | TestWindowNativeReadSetAndEpoch |
| G16_GENERIC_SLASH_MAPPING | Any slash/colon name/version equivalence | TestClosedTransitionMapping |
| G16_NULL_TABLE_HISTORY_SKIP | A null table skips retained-burn history validation | TestTimeUseReopenRejectsDeletedTable |
| G16_PRODUCTION_FIXTURE_WITNESS | An accepting synthetic witness replaces ClosedWitness in the factory | TestProductionDependenciesClosed |

`TestWindowLateCommitForbidden` models a pause before the complete endpoint:
X/TLS must keep a held burn without recording authority. Its paired timely
control is `TestWindowTimelyEndpoint`. `TestWindowPostCommitPause` instead pauses
at delivery after a timely authority commit and retains that authority without
an application effect. The private runtime's `Execute` must enclose the entire
endpoint callback, including the durable commit; the tagged implementation is
only a deterministic model. Native enforcement through callback completion is
still PENDING.

There are no intentionally surviving mutants. `TestWindowTerminalPurity` also
plants extra reads, witness/original-reader work and an ordinary clock call at
the terminal boundary and requires the intended structural rejection. This is
a bounded source instrument, not proof against arbitrary obfuscated/dynamic code.
`TestXPostSendAccountingFailure` pairs a full synthetic frame with separate
successful or write/sync/readback/crash-failed non-authoritative local accounting,
then reopens exact authority and verifies that the burned slot cannot redispatch.
It does not establish actual socket/device/scheduler bounds or macOS semantics.

## Qualification specifications

These names are documentation specifications only. The CI reporter lists every
PENDING row; no placeholder test body reports native qualification as passing.

| Specification | Status | Required input / evidence |
| --- | --- | --- |
| TestWC1NativeQualification | PENDING | P/R/X/TLS installed clock/boot, suspend/restore, entropy, epoch, storage/workload and identical native endpoints; no synthetic runtime |
| TestWC1EnforcedPostReadBound | PENDING | effect-enforced original exclusive D and current epoch through all four full endpoints, including positive f_X_commit/f_X_send within original f_X; native pause/preemption/storage-stall controls |
| TestWC1RealUseCustody | PENDING | independently current full S3 use/root ancestry and original lineage, rollback/replacement exclusion, retained tombstones and qualified hard capacity/barriers |
| TestWC1RealWitness | PENDING | reviewed installed independent confirmed witness backend, authenticated current checkpoint/ancestry and live invalidation without a WC1 time dependency cycle |
| TestWC1RealOriginalReader | PENDING | installed qualified bounded complete original reader/validator with protected descriptor provenance, live custody and revocation through completion |
| TestWC1MacOSParity | PENDING | separately reviewed Darwin receipt/domain mapping, mach_continuous_time, boot UUID, checked F_FULLFSYNC and independently proven namespace/act durability for P/R/X/TLS, including X post-send accounting crash pairs |
