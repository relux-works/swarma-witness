---
name: swarma-witness
description: Use Swarma Witness's Go codecs, signed evidence and unserved policy/storage components, or integrate its caller-supplied callbacks. Use for this module's contracts and refusal boundaries.
---

# Swarma Witness

Use the Go module `github.com/relux-works/swarma-witness` for bounded wire, record and evidence handling. It supplies libraries, not a served or qualified witness. There is no witness service CLI, listener or production signer. Consumers remain in mode A until their applicable activation gates close; a decoded request, valid signature or local transaction check does not establish authoritative append/latest or recovery authority. See the [module overview](../../../README.md).

Read [codec usage](references/codecs.md) for request decoding, protected bindings, consumer records, receipt/head/page checks and an inert fixture with its nearby refusal. Read [extension boundaries](references/extensions.md) when supplying a signer or TLS time source, investigating storage fault injection, or assessing custodian/archive integration. Use the linked source symbols for exact signatures and the local specifications for schemas; do not turn a proposal into an implemented operation.

Preserve original LF-inclusive record bytes, protected profiles, separate writer/witness keys and caller-held anchors. Canonicalization is for constructing new values, not repairing received evidence. Shape checks grant no peer or stream authorization. Head verification still requires the caller's trusted-anchor comparisons and verification of every referenced page and its records.

For serving requests, report the actual closed boundary: `service.New` installs closed dependencies and no store or signer; `config.DisclosureGate` and `config.CustodyGate` have no override. Internal qualified-time fixtures cannot activate production. Keep uncertain transaction evidence and hold rather than inventing recovery, regenerating receipts or inferring genesis from missing storage. Return the actual refusal and the precise scope established by the check.
