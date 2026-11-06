# Codec usage

Import packages under `github.com/relux-works/swarma-witness`. The [wire contract](../../../../spec/wire-v1.md) defines the schemas; the implementation below defines the callable surface.

## Decode without granting authority

- Use [`wire.DecodeRequest`](../../../../wire/request.go) on exact canonical frame bytes. Its closed methods are `append`, `latest`, `proof_page` and `admin`; these are decoded method names, not callable network endpoints. The envelope requires `v`, `request_id`, `timeout_ms`, `method` and `params`; timeout is 1–5000 ms. A `wire.Request` proves shape/encoding only.
- [`wire.Parse`, `wire.Canonical` and `wire.Line`](../../../../wire/canonical.go) enforce exact canonical input and line framing. Records have one terminal LF, included in their hashes; do not strip it or reserialize received evidence. Use `int64` for integers when constructing canonical values. Limits include 65536-byte frames, 8192-byte lines, 4096-byte receipts, 32768-byte heads and 45056-byte pages. Binary carriers use strict unpadded base64url via `wire.DecodeBinary`.
- Decode protected bindings with [`wire.DecodeBinding`](../../../../wire/binding.go); its zero value is invalid. A binding is not provisioning or consent evidence. Its consumer/profile choice is closed: Keymaker, registrar SHA-1/SHA-256 or owner-registry checkpoint. Signing-key IDs hash raw Ed25519 key bytes; `wire.TransportPin` hashes canonical DER SubjectPublicKeyInfo. Never interchange these representations.
- For protected policy checks, [`config.Parse`](../../../../config/parse.go) returns `config.Protected`; parsing does not open production gates. [`transport.ValidateAuthorizedFrame`](../../../../transport/authorize.go) calls `policy.Snapshot.Authorize` before inner request decoding. It is a pure predicate with no dispatcher or content lookup; [`transport.DecodeHTTP`](../../../../transport/handler.go) is also a decoder, not a listener.

## Check consumer records and evidence

- [`records.DecodeKeymaker(line, binding, bootstrapPair)`](../../../../records/keymaker.go) checks the signed record against its protected binding. Supply explicit bootstrap context; this is not permission to bootstrap. The returned `records.Record` retains the original line and binding; `Line()` returns a copy and `Hash()` hashes those LF-inclusive bytes. Validation does not prove candidate-state truth or semantic intent/commit pairing.
- [`records.DecodeRegistrar(line, binding, bootstrapFirst)`](../../../../records/registrar.go) checks flat line syntax and the protected profile's revision format, not authenticated append or Git contents. `records.CheckRegistrarRevision` chooses 40 or 64 lowercase hex characters from the profile, never from the received ID's width. [`records.DecodeCheckpointWrapper`](../../../../records/checkpoint.go) retains originals but returns no admitted record; `CheckpointWrapper.Verify()` always refuses `profile_unavailable`.
- [`evidence.VerifyReceipt`](../../../../evidence/receipt.go) compares the signed receipt to the exact record, binding, witness key and control hash supplied by the caller. [`evidence.VerifyHead`](../../../../evidence/head.go) additionally checks the original receipt, challenge and structural continuity, with separate current and historical witness contexts. Compare manifests to the requested trusted anchors and verify all referenced pages before claiming latestness.
- [`evidence.VerifyPage`](../../../../evidence/page.go) checks canonical bytes, hash and entry framing. It does not check record signatures, pairing or membership in a trusted fresh head. A cached page alone proves no latestness. Keep these caller obligations separate from successful codec verification.

## Inert fixture and nearby refusal

Inside a Go caller importing `github.com/relux-works/swarma-witness/wire`, the following uses the decoded bytes of the public corpus's `canonical` and `space` cases. It performs no IO or service operation:

```go
raw := []byte(`{"method":"proof_page","params":{"page_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","stream":"fixture-stream"},"request_id":"cccccccccccccccccccccccccccccccc","timeout_ms":5000,"v":1}`)
req, err := wire.DecodeRequest(raw)
// err == nil; req.Method == "proof_page".

_, refusal := wire.DecodeRequest(append([]byte(" "), raw...))
code := wire.Code(refusal)
// code == "request_malformed": a leading space is not canonical.
```

These expectations come from [`testdata/witness-v1/wire.json`](../../../../testdata/witness-v1/wire.json) and [`TestWireVectors`](../../../../wire/vectors_test.go). The page hash is inert fixture data; no page is fetched or authenticated. This is a caller excerpt, not a new module function or proof of deployment readiness.

For responses, [`wire.DecodeResponse`](../../../../wire/request.go) returns a decoding error separately from an application refusal in `Response.Error`; inspect both. [`wire.Code` and `wire.Retryable`](../../../../wire/errors.go) expose closed refusal semantics. Only `busy` and `rate_limited` are marked retryable; `outcome_unknown` is not an instruction to replay an effect.

When corpus integrity is the task, the existing offline command is `go run ./tools/vectors -check` from the checkout root ([implementation](../../../../tools/vectors/main.go), [data contract](../../../../testdata/witness-v1/README.md)). It checks the manifest and declared bytes; it does not qualify the protocol or install a witness command. This guide does not require running it for ordinary codec use.
