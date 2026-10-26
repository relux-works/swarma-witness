# S3 local transaction tests

These are executable synthetic control-flow checks, not deployment qualification.
Run `make test-storage`; bounded race checks cover CAS and exact retry only:
`go test -race ./service -run '^Test(CASRejectsGapAndConcurrentLoser|OccupiedPositionRequiresExactBytesAndPredecessor)$' -count=1 -timeout=90s`.
The [local contract](storage-v1.md) states codecs, barriers and closed defaults.

| Test | Specific claim and paired control | Narrowing mutant / intended assertion |
| --- | --- | --- |
| TestCASRejectsGapAndConcurrentLoser | Stale predecessor/gap refuse head_conflict; exact next record commits/reopens, distinct concurrent loser has no second effect. Busy is a bounded contention result. | M03_SKIP_HEAD_CAS: CAS expected predecessor |
| TestOccupiedPositionRequiresExactBytesAndPredecessor | Changed occupied bytes refuse position_conflict; wrong predecessor refuses head_conflict; original retry is byte-identical, audited, no signing. Protected writer-policy epoch change is modeled locally, not qualified rotation. | M03_RETRY_BY_DIGEST_ONLY: digest equality cannot replace exact bytes; M03_RETRY_NEW_RECEIPT: retry creates no new receipt |
| TestPreparedReceiptCannotEscapeBarriers | Every actual write/sync/close/rename/directory-sync call in the successful trace is blocked then failed; no early response, uncertain append holds. Complete barriers and retained reopen are positive controls. | M03_RETURN_PREPARED_RECEIPT: external barrier holds receipt; M03_SKIP_DIRECTORY_SYNC and M03_RENAME_BEFORE_SYNC: full barrier order |
| TestAdminActivationIsAtomicWithHistory | Failed custody keeps old key/policy; success retains old-key receipt, atomic new-key activation and exact action replay after reopen. | M03_ACTIVATE_KEY_BEFORE_CONTROL_ACK: new key activated before control ack |
| TestAuditFailureClosesAdmissionWithoutRecursion | Archive failure prevents append/retry release; reentrant append is busy; audit exhaustion and default reader deny. Valid independent ack commits. | M03_RELEASE_WITHOUT_AUDIT: retry requires durable audit; M03_AUDIT_APPEND_RECURSION: audit append recursion denied |
| TestStorageReserveAndRetentionFailClosed | Coherent old snapshot fails independent check before work; full logical history changes no root and deletes no retained entry. Closed custodian signs/writes nothing; authorization precedes inner evidence. | M03_LOCAL_HASH_ONLY: local hash alone cannot accept rollback; M03_DELETE_HISTORY_ON_FULL: full history must not be deleted |
| TestReviewerPhaseLinksAgreeOnReopen | Three independently inconsistent prepare/segment/outcome links refuse storage_unavailable on Inspect; valid closure reopens unchanged. The prepare-segment fixture keeps outcome-prepare consistent to isolate the broken link. | M03_SKIP_OUTCOME_PREPARE_LINK: inconsistent outcome-prepare link accepted on reopen |
| TestReviewerReadAuditReserveClosesAdmission | Both latest/proof_page fence audit-full, local-storage and independent-storage failures before releasing admission; preflight leaves root unchanged and a later append signs nothing. Available audited read remains ready. | M03_SKIP_READ_AUDIT_FENCE: audit reserve loss must close admission |

`python3 .github/scripts/check-s3-controls.py` runs a green unchanged control and
isolated source overlays for all thirteen mutants above. Each mutant must exit1 at the
named test assertion. Compilation, setup failures, timeouts and missing assertion
text are survivors. The recursion mutant removes both bounded reservation-entry
guards; it does not cover all conceivable recursive logging designs. The digest
collision is a private boolean model, not a claimed SHA-256 collision. The barrier
harness injects calls on an isolated filesystem fixture, never host/device faults.
No power-loss, controller-cache, filesystem-recovery or distributed-exclusion
qualification follows from green tests. No surviving mutant is claimed covered.

Additional scoped tests:

| Test | Specific claim / limitation |
| --- | --- |
| TestPreparedLocalCodec | Exact original LF survives; checksum, closed manifest version/members, truncation, excess bytes and complete envelope cap reject. |
| TestStorageProtectedFilesAndShortWrites | Native short writes complete; zero-progress, changed immutable name, symlink, hardlink, wrong modes and traversal reject on isolated Linux amd64 descriptors. No privileged owner/mount manipulation is exercised. |
| TestStorageMissingGenesisAndDamage | Missing root cannot infer genesis; unknown magic rejects. |
| TestAuditClosedSchemaAndGlobalOrder | Interleaved stream names share one sequence/hash predecessor; wrong predecessor, null-time success, unknown members and codes reject. This is a pure codec, not two independently serving instances. |
| TestAdminActivationProofClosure | Retains exact consent/first-line/packet/object bytes in local restricted evidence, refuses over-cap closure; no approval authority is inferred. |
| TestAuditClosedServiceStreams | Two distinct stream appends, exact retry and refused latest publish four linked retained audit originals; lookup/read add no consumer record. |
| TestPreparedReopenRejectsUnpublishedEvidence | Failed sync retains unpublished inventory and refuses reopen rather than silently serving old root; no repair or power-loss claim. |
| TestAuditReadersAndBoundedHealth | Explicit global principal/pin membership only; copied grants, duplicate-pin rejection, saturating fixed counters and bounded diagnostic allowance. |
| TestArchiveExactRetrievalAndSeparateAnchor | Test-only archive retains exact bytes and checks length/hash; anchor advancement needs distinct approval/continuity/fresh-head facts and rejects replay. No durable approval or real provider is modeled. |
| TestArchiveDefaultsClosed | Production retention/retrieval/audit refuse storage_unavailable; unaccepted offline verification/advancement refuse profile_unavailable. |
| TestReviewerCheckedCloseBeforeRename | A checked-close error prevents rename, paired with exact completed-root reopen; retained reviewer control. |
| TestReviewerReopenDamage | Truncation, damaged original, unknown/staged names and multiple links refuse Inspect; isolated local fixtures only. |
| TestReviewerCustodyUnlockedAndStopCloses | Custody holds no final local gates; stop during confirmation prevents release/publication, paired with completed transaction. |
| TestServiceDependenciesStayClosed | Closed time/exclusion/recovery prevents root publication; test-only accepting facts isolate each dependency. |

No attack-surface table was supplied with this slice; this test map is not an
exhaustive surface-coverage claim. No existing reviewer tests are removed. No WS
member is treated as a successful out-of-contract fallback: latest/proof success,
other consumer dispatch, G16–G19 qualified providers, migration/recovery and live
serving remain unavailable under the explicit excluded scope and later G21/G22.

## PENDING qualification specifications

The reporter inventories these documentation rows. They are not skipped tests,
executable green placeholders or qualification claims.

| Test specification | Status | Required independent evidence |
| --- | --- | --- |
| TestStorageCustodianFreshnessAndSLA | PENDING | Owner-selected independent provider, accepted exact signed protocol and challenge/epoch/ancestry verification, retention/latestness and whole-call SLA. |
| TestStorageLifetimeExclusion | PENDING | Enforced exclusion of paused/partitioned/restored old instances through actual effects and response release. |
| TestStorageExactRecoveryAndGenesis | PENDING | Independently authorized genesis, exact pending/outcome recovery, retained burns, joint-loss runbook and no reset/re-signing. |
| TestStorageQualifiedTimeWindows | PENDING | Accepted WC1 Linux/macOS profiles and use transitions, original deadlines, qualified entropy, native handoff closure and enforced read-to-act endpoint. |
| TestStorageDeviceAndArchiveRetention | PENDING | Real isolated device power-loss/namespace durability, hard reserve, protected ownership/mount layout and independently retrievable immutable archive. |
| TestCustodianIndependentIdentity | PENDING | Independent administration/keys/epochs/pins and recovery domain: valid separately enrolled provider is the positive control; shared/derived primary key, common administrative token, wrong pin/epoch or cross-consumer scope refuses without confirmation/disclosure. Plant acceptance of a primary-derived identity; require the independent-identity assertion to fail. |
| TestCustodianComparePrevious | PENDING | Durably confirm a valid exact predecessor/successor and recover the original exact repeat; changed occupied bytes/transaction/evidence, stale predecessor and concurrent distinct loser cannot advance, overwrite or obtain another confirmation. Plant requester-selected predecessor or digest-only retry; require the corresponding exact-position assertion to fail. |
| TestCustodianOriginalEvidence | PENDING | Valid complete independently authenticated record/receipt/control/key ancestry permits confirmation; digest-only, replica-only, missing original, bad pairing/signature or truncated/over-limit closure refuses before retention/ack. Block/fail every actual durability barrier and require no early confirmation with exact held state. Plant ack-before-retention or omitted original validation; require the named barrier/original assertion to fail. |
| TestCustodianFreshControl | PENDING | Valid fresh challenge/scope/provider-epoch and independently current control permits the read; replayed challenge, cached response, wrong scope/epoch, stale control paired with fresh record, substituted historical control_hash or missing ancestry refuses with no release. Plant cached freshness or skip current-control comparison; require the corresponding freshness assertion to fail. |
| TestCustodianUnknownOutcome | PENDING | Completed valid confirmation/publication is the positive control; lose reply or crash before/after remote durable retention, local root and response release. Preserve exact originals/pending outcome and hold ambiguity; exact reconciliation returns only original authorized outcome, never re-signs or sends late. Plant timeout-as-no-effect/new-ID retry; require the original-outcome assertion to fail. |
| TestCustodianEitherSideRestore | PENDING | Valid evidence-bound recovery reconciles exact surviving originals with independent latest anchors while old executors are fenced. Coherent rollback of primary, custodian or both, custodian ahead/behind, missing original and joint-loss ambiguity hold without reset/copy-as-authority. Plant primary-transfer catch-up or larger-sequence selection; require the independent-recovery assertion to fail. |
| TestCustodianAuthorizedContinuity | PENDING | Explicit independently authorized genesis and pin/epoch rotation/migration preserving full acknowledged ancestry are positive controls; missing/restored state, copied key, unapproved pin change or mutual confirmation cycle never creates a lineage. Plant missing-state genesis or circular trust acceptance; require the continuity assertion to fail. |
| TestCustodianLifetimeExclusion | PENDING | Qualified current owner completes write/sign/release and emergency stop remains reachable. Pause/partition/revoke/replace/restore/clone before and after preparation and while external calls are unlocked: old/delegated executors cannot actually write, sign or emit prepared responses, including after resumption. Plant CAS/heartbeat/point-check-only fencing; require the actual-effect assertion to fail. |
| TestCustodianDeadlineAndInventory | PENDING | A complete bounded inventory/call/evidence workload completes strictly within every original deadline; 201 serial heads under the stated 5 s assumptions, missing/over-limit envelope, deadline equality, loss beyond reserve, extra under-lock RPC and post-read pause refuse with no late act/release. Plant omitted inventory, fresh retry clock or under-final-lock RPC; require the corresponding completeness/deadline/purity assertion to fail. |
| TestCustodianConsumerCoverage | PENDING | Each accepted Keymaker bootstrap/enrollment or broker settlement mapping has a valid full-inventory original transition/recovery. Roll back its allocator/results, stage/association, approval/high-water/ledger, use/outcome or W/hold/original ancestry, or substitute another scope/epoch: hold/refuse, no repeated authority. Plant record-head-only coverage or truncated uint64-to-WS conversion; require the complete-binding assertion to fail. D5/PC2/A3d-2 need their own accepted mapping controls, not equivalence by this test name. |
| TestCustodianNativeParity | PENDING | Qualify each exact Linux/macOS tuple independently with authentic provider/time/custody/exclusion/original-reader and enforced full endpoints; nearby on-time valid controls succeed. Absent/unqualified dependencies, expired authority, deadline equality and old restored executors refuse without late effects. Plant cross-platform evidence reuse; require the exact-platform assertion to fail. No present synthetic test supplies this evidence. |

The new custodian rows specify the [G17/G18/G19 proposal](custodian-v1.md).
All listed controls are future requirements, **not executed mutants or native
qualification**. Valid positive controls must fail under blanket denial, so an
implementation that rejects everything cannot satisfy these requirements.
Neither the second-witness placement nor an arithmetic budget fit closes a gate.
