# Extension boundaries

There is no plugin loader, registry or registration command. The usable seams are explicit Go callback/interface arguments. Do not invent a plugin manifest, discovery directory or registration API.

## Signer callback

Write a function matching [`records.Signer`](../../../../records/signature.go): `func([]byte) ([]byte, error)`. Sign the supplied preimage exactly and return its 64-byte Ed25519 signature. The module constructs the domain-separated canonical preimage, reserves the bounded artifact before calling the signer, snapshots the body and independently verifies the returned signature against the supplied `records.Key`. The caller provides key custody; the library supplies no production private-key implementation.

There is no registration step. Pass the callback as the `sign` argument to `records.SignEnvelope`, [`evidence.NewReceipt`](../../../../evidence/receipt.go), [`evidence.NewHead`](../../../../evidence/head.go) or [`evidence.NewControlReceipt`](../../../../evidence/control.go). Select the domain and key role from protected context. With otherwise valid inputs, a nil or failing callback yields `profile_unavailable`; a wrong-length or invalid signature yields `evidence_invalid`. Generic `records.VerifyEnvelope` still requires the caller to check the domain's exact body schema; prefer the artifact-specific evidence functions for those artifacts.

For isolated callback checks, follow [`TestEvidenceCopiesOriginalWriterFields` and `TestEvidenceSignerBoundary`](../../../../evidence/evidence_test.go): a fixture signer produces a receipt accepted by `evidence.VerifyReceipt`; altered signed projections refuse; invalid receipt input and oversized envelopes make zero signer calls; callback mutation cannot replace the reserved body. These are existing test patterns, not production custody qualification or a new plugin test runner.

## TLS time-source interface

Implement [`transport.QualifiedTime.Consume(context.Context, transport.TimeRequest) (transport.TimeFacts, error)`](../../../../transport/tls.go) only against its full consumption contract. The provider must verify authenticated receipt/closure, current boot, one-use challenge and protected policy, and durably consume observations before returning. Returning timestamps or a trusted boolean is insufficient; failed TLS admission does not undo consumption.

Pass the implementation directly as `source` to `transport.ValidateTLS(ctx, c, presented, id, challenge, source)` or `transport.TLSConfig(c, source)`. `c` is a protected `transport.TLSContext`; no peer-selected root or pin becomes protected configuration. There is no registry and no production time provider supplied here. The predicate compares returned facts with the exact requested context and interval bounds; missing or mismatched facts refuse `profile_unavailable`.

For isolated implementation checks, use the patterns in [`TestTLSRefusesWithoutQualifiedTime` and `TestTLSRejectsUnpinnedAndWrongRoleKeys`](../../../../transport/tls_test.go). They pair a synthetic consumed-time control with nil-source, wrong boot/challenge/operation, missing continuity and interval refusals, and retain the provider call count. Such fixtures do not qualify a native source or a CA. The separate [internal WC1 adapter](../../../../spec/qualifiedtime-v1.md) is not an external plugin API; its production constructor remains closed even with fixture tags.

## Contracts that do not enable serving

[`custodian.Provider`, `custodian.Exclusion`, `custodian.Recovery`, `custodian.Time`](../../../../custodian/contract.go) and [`archive.Consumer`, `archive.Audit`](../../../../archive/contract.go) are typed obligations with closed defaults. They have no public registration or injection path into [`service.New`](../../../../service/barrier.go). Its dependency fields are private; the constructor installs closed providers and no store or signer. Implementing an interface alone cannot wire or activate this service. The [custodian protocol](../../../../spec/custodian-v1.md) remains a proposal, not an implemented provider wire format.

[`store.Calls`](../../../../store/transaction.go) injects filesystem calls through `store.Open` or `store.Inspect` for isolated fault checks. Nil fields use native IO; this is not an inert mock or a production admission seam. Those functions inspect existing protected storage, never create genesis; opening storage does not establish readiness. Use the [local storage contract](../../../../spec/storage-v1.md) when handling retained evidence. No recovery initializer or automatic repair is supplied.
