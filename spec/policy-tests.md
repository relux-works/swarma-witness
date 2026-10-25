# S2 validation and remaining qualification

Run `go test ./policy ./config ./transport -run 'Test(ACL|Provision|Admin|Rotation|TLS)' -count=1`,
`go build ./...`, `go vet ./...`, formatting, module tidiness, hygiene, vectors and
dependency policy. These tests use synthetic roots/facts only. Existing reviewer
and S1 tests retain their names and sources. No full service suite or deployment
qualification is implied.

| Test | Claim | Narrowing mutant |
| --- | --- | --- |
| TestACLRejectsCrossStreamAndRegistryWriter | Exact stream membership; publisher cannot become bridge/admin | M02_ACL_STREAM_WILDCARD; M02_GIVE_PUBLISHER_BRIDGE_ROLE |
| TestProvisionRequiresConsentAndExactBootstrap | Signed consent/exact grant required; empty state grants nothing | M02_INFER_BOOTSTRAP_FROM_EMPTY |
| TestAdminRejectsReplayAndRoleOverlap | Changed action-ID reuse refuses; exact action retains original result | M02_IGNORE_ADMIN_ACTION_REUSE |
| TestRotationPreservesHistoricalAuthority | Current writer only; unchanged key/epoch and exact original historical receipt; changed key refuses despite valid signatures | M02_REAUTHORIZE_OLD_WRITER; M02_ALLOW_RECORD_KEY_ROTATION |
| TestTLSRejectsUnpinnedAndWrongRoleKeys | Path+pin+role+interval/CRL predicates jointly required | M02_ACCEPT_UNPINNED_TLS |
| TestProvisionG07RemainsClosed | Valid config cannot open disclosure approval | M02_OPEN_G07_GATE |

Other named controls include TestAdminG10RemainsClosed,
TestRotationPossessionEvidenceBound, TestACLTransportFramingAndBudgets,
TestACLTransportAuthorizesBeforeInnerEvidence, TestACLRateBudgetControls,
TestTLSRefusesWithoutQualifiedTime, TestTLSMutualHandshake,
TestTLSRejectsUnknownSAN and TestTLSProposedPreimageVectors. Mutants are isolated
source overlays, not runtime switches. A kill requires the named test's intended
assertion, not a compiler/setup failure. Unassigned controls have no claimed
mutation coverage. The time source in tests models verified/consumed facts;
passing it does not qualify a provider, complete receipt verifier or live handoff.

The following are **PENDING test specifications**, not executable green tests or
skipped test bodies. They must be implemented with their dependency; no t.Skip or
passing placeholder substitutes for these claims.

| Test specification | Status | Dependency / missing proof |
| --- | --- | --- |
| TestProvisionDurableConsentConsumedOnce | PENDING | S3/S4 atomic reservation, first-append consumption and original retry receipt under crashes |
| TestAdminDurableOneUseID | PENDING | S3/S4 durable original ID/action/result and uncertain-outcome reconciliation |
| TestRotationDurableBarrierAndHistoricalReceipts | PENDING | S3/S4 atomic credential retirement, settled streams and old-key control receipt |
| TestRecordRotationRejectsTransplantedPair | PENDING | Joint KC/internal-writer option-A contract; A-to-B pair transplant with same head/candidate refuses with unchanged binding/head/replay/bootstrap; same-action/challenge positive control only after acceptance |
| TestRecordRotationExactReplayPreservesResult | PENDING | Joint KC/internal-writer option-A contract plus S3/S4 original result retention; exact settled A replay retains result, including accepted receipt; S2 refusal never creates receipt/cache authority |
| TestTLSQualifiedTimeAdmissionHandoff | PENDING | G11/G16 accepted complete native adapter, qualified provider consumption/continuity and bounded fresh application-admission handoff |
| TestTLSRevocationReloadCancelsSessions | PENDING | S3/S4/G11 protected atomic reload, retained CRL high-water and cancellation/current-generation recheck |
| TestTransportStreamingBoundsAndNoLateEffects | PENDING | S3/S4/G20/G27/G28 bounded I/O, monotonic cancellation, tables/fairness and uncertain-effect fencing |
| TestProvisionOwnerDisclosureApproval | PENDING | G07 owner approval/accepted authority contract; gate has no config override |
| TestAdminQualifiedCustodyAndInitialPins | PENDING | G10 owner provisioning, independent custody and continuity qualification |

No surface table was supplied in the implementation brief; the named plan rows
above are the scoped coverage map, not an exhaustive attack-surface claim. Durable
service behavior and provider qualification remain out of this pure-validation
slice under its explicit S3/S4/G07/G10/G16 dependencies.
