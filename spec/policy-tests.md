# S2 validation and remaining qualification

Run `go test ./policy ./config ./transport -run 'Test(ACL|Provision|Admin|Rotation|Review)' -count=1`,
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
| TestReviewObserverScope | Observer reads only explicitly provisioned stream and pin; a second stream remains undisclosed | RW1_OBSERVER_ALL_STREAMS; RW1_OBSERVER_IGNORE_PIN |
| TestReviewProspectiveSigningRoles | New record/witness keys cannot reuse the admin signing key; refusals return no plan | RW1_ADMIN_AS_NEW_RECORD; RW1_ADMIN_AS_NEW_WITNESS |
| TestReviewHTTPInteriorControl | Ordinary ASCII and edge OWS pass; interior HTAB closes without frame | RW1_ALLOW_INTERIOR_HTAB |
| TestProvisionG07RemainsClosed | Valid config cannot open disclosure approval | M02_OPEN_G07_GATE |

Other named controls include TestAdminG10RemainsClosed,
TestRotationPossessionEvidenceBound, TestACLTransportFramingAndBudgets,
TestACLTransportAuthorizesBeforeInnerEvidence, TestACLRateBudgetControls
and the reviewer regression names above. The four original policy plan rows
and seven original non-TLS mutants belong to this policy/HTTP slice. TLS tests,
`M02_ACCEPT_UNPINNED_TLS` and all proposed G11 codec evidence belong only to the
separate G11 commit and are not claimed as policy-slice execution evidence.
Mutants are isolated source overlays, not runtime switches. A kill requires the named test's intended
assertion, not a compiler/setup failure. Unassigned controls have no claimed
mutation coverage. Future qualified-time test sources model verified/consumed
facts only; passing them cannot qualify a provider, complete receipt verifier or live handoff.

CI runs `.github/scripts/report-pending.sh` to discover these documentation rows
and compare them against the independent `pending-rows.txt` lower bound. It reports
new rows automatically and fails on removed rows or empty discovery. The isolated
`check-pending-controls.sh` fixtures check those refusals with no partial report;
reporter success is inventory evidence only.

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
