# Wire verification scope

Run `make test-wire` for the bounded package tests, `make vectors` for manifest
integrity, and `go build ./wire ./records ./evidence` for compilation. Run the
hygiene tool before publication. These commands establish codec properties only;
review separately exercises the wider repository. No network, power-loss,
filesystem durability, custodian, restart, exclusion or production signer is
qualified here. There are no third-party fixture bytes or copied verifiers.

Each test states its claim beside its declaration and includes valid controls.
Named tests from the wire slice and its narrowing mutants are:

| Test | Specific claim | Narrowing mutant |
| --- | --- | --- |
| TestWireRejectsNoncanonical | Canonical byte equality and duplicate/alias refusal | M01_ACCEPT_DUPLICATE_ALIAS |
| TestRecordBindsLFDomainAndProtectedType | Complete LF-inclusive hash and protected independent domain | M01_HASH_WITHOUT_LF; M01_DOMAIN_FROM_BODY |
| TestWireChargesDecodedAndEncodedBounds | Raw/encoded caps, depth, arrays, ordinary/carrier distinction | M01_SKIP_CARRIER_CAP |
| TestRecordsReserveIntentResolutionRoom | Final intent refuses; preceding intent/final resolution fit | M01_ALLOW_FINAL_INTENT |
| TestEvidenceCopiesOriginalWriterFields | Receipt writer projection survives distinct witness epoch | M01_OVERWRITE_WRITER_WITH_WITNESS |

These mutation names describe isolated source overlays, never runtime switches.
The duplicate mutant retries a failed strict parse through a lossy duplicate-
collapsing JSON reader; the domain mutant trusts a received domain claim. The
other controls remove exactly their named guard/projection. A kill requires the
named test's assertion failure, not compilation/setup failure. They narrow these
properties, not universal conformance or every possible malformed input.

The accepted decision's additional groups map to executable tests as follows:

| Decision pair | Test | Important boundary |
| --- | --- | --- |
| S1-BindingShape | TestRecordsS1BindingShape | Three closed variants; parsing is not provisioning |
| S1-BindingBounds | TestRecordsS1BindingBounds | Service/stream 128/129, station 63/64, UTF-8 bytes 255/256, writer/reader pins 8/9, readers 32/33 |
| S1-KeyAndPinRepresentations | TestRecordsS1KeyAndPinRepresentations | Independently derived raw32 ID and DER SPKI hash |
| S1-RoleSeparation | TestRecordsS1RoleSeparation | Protected signature roles only; peer ACL/bridge separation remains S2 |
| S1-Ed25519Points | TestRecordsS1Ed25519Points | Public and R point negatives, including stdlib-valid identity/mixed equations |
| S1-ScalarAndEncoding | TestRecordsS1ScalarAndEncoding | S=L, lengths, padding and unused bits |
| S1-DomainAndRole | TestRecordsS1DomainAndRole | Otherwise valid wrong-domain signatures and protected purpose/role |
| S1-EnumsAndNulls | TestRecordsS1EnumsAndNulls; TestRecordsBootstrapNulls | Exact commit classes, kinds, explicit bootstrap nulls |
| S1-CheckpointOriginals | TestRecordsS1CheckpointOriginals | Exact carried bytes and closed projection; verifier always unavailable |
| S1-RegistrarRevision | TestRecordsS1RegistrarRevision | Both protected-format positives pass; other-format IDs refuse without algorithm inference |
| S1-RegistrarDigest | TestRecordsS1RegistrarDigest | D syntax versus well-formed substituted evidence |
| S1-ResultCarrier | TestWireS1ResultCarrier | Same non-null canonical binary carrier for all methods |
| S1-FrameBounds | TestWireS1FrameBounds; TestWireLineBoundaryAndMethods | Independent raw/encoded/metadata/frame ceilings; no claim all are reachable together |
| S1-Correlation | TestWireS1Correlation | Untrustworthy ID gives no frame; valid ID supports closed refusal |

`TestEvidenceHeadAndPage` covers equal-anchor original receipt, changed challenge,
incomplete manifest and page-hash/chain refusal. `TestEvidenceControlSchemas`
covers signed provision and control receipt, forbidden null and operation.
`TestEvidenceSignerBoundary` proves rejection before external signing and body
snapshot isolation during callbacks. `TestWireErrorsClosed` checks all 18 fixed
codes/retryability and rejects extra error members. `TestWireDependencyPins`
checks exact approved module metadata against old/unreviewed pins. Frozen corpus
consumers are `TestWireVectors`, `TestRecordsVectors`, `TestEvidenceVectors`;
record/receipt signatures are also checked independently with literal domains and
stdlib Ed25519. These are first-party codec controls, not consumer integration.

The plan assigns the six M01 mutants above. Additional pair tests have no
plan-assigned mutant; their assertions are not represented as exhaustive mutation
coverage. Transport no-foreign-disclosure tests, complete admin authorization,
registrar candidate truth and registry originals/signature/ancestry verification
belong to their later gated slices. No successful test clears those gates.

`TestRecordsRegistrarFields` checks the flat registrar schema and independent
bootstrap/exhaustion guards. `TestEvidenceRegistrarProjection` checks neutral
domains, original writer projection across rotation, and digest substitution.

Two additional narrowing controls cover the activated registrar path:

| Mutant | Property | Named failing test |
| --- | --- | --- |
| M01_REGISTRAR_LENGTH_DEFAULT | A request length cannot select an admitted format | TestRecordsS1RegistrarRevision |
| M01_REPLACE_NEUTRAL_WRITER | Neutral receipt retains original writer epoch | TestEvidenceRegistrarProjection |

`TestEvidenceRotationSchemas` covers valid writer/witness rotation shapes and
wrong-domain new-key proof. `TestRecordsRegistrarVectors` and
`TestEvidenceRegistrarVectors` consume the frozen registrar format/receipt pairs.
