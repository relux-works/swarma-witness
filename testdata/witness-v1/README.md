# Witness vector data

This repository is the authoritative source of witness vectors. The manifest
contains first-party S1 codec fixtures. No third-party fixture
data is included. `wire.json` carries a valid request and four negative twins;
`keymaker.json` carries a closed binding, a signed bootstrap intent and independently
signed wrong-domain twin, a frozen LF-inclusive hash, and a signed receipt with
distinct writer/witness epochs. Public keys are disposable fixture identities,
not deployment pins. `registrar.json` binds the landed spec revision and carries
both protected formats, wrong-format twins, LF hashes and neutral receipts. No private keys are distributed. Tests never regenerate
these bytes and also check signatures using literal domains and stdlib Ed25519.

Manifest version 1 is a closed JSON object with exactly `schema` (integer 1) and
`files` (array). Each entry has exactly `path`, `size` and `sha256`. Paths are
unique, strictly increasing bytewise, relative to this directory, and cannot be
absolute, traverse parents or follow links. `size` counts exact bytes, including
any LF; `sha256` is lowercase 64-character SHA-256 of those same bytes. Metadata
accepts JSON whitespace but rejects duplicate/unknown members and trailing data;
it is not a CCJ-1 wire encoder. Limits are 1 MiB metadata, depth 16, 1024 files,
4 MiB per file and 16 MiB aggregate data. README.md and manifest.json are reserved;
other files must be declared. These tooling limits are not service admission
limits. Adding normative vector types or raising bounds requires review.

Consumers take immutable data, without copying implementation code. Their closed
version-1 lock has exactly these members:

```json
{"schema":1,"repository":"github.com/relux-works/swarma-witness","commit":"<full-reviewed-commit>","manifest_sha256":"<exact-manifest-sha256>"}
```

The placeholders above are explanatory and are refused by the checker. The real
commit is a full lowercase 40-digit Git object ID, not all zeroes; the digest is
64 lowercase hex digits of the exact manifest bytes. A consumer first checks out
the reviewed corpus commit and stages it offline, then runs:

```sh
go run ./tools/vectors -check -root <corpus-checkout> -lock <consumer-lock.json>
```

The tool compares the lock to actual checkout HEAD and manifest bytes, then
checks every declared file. It neither fetches nor invents a lock. No local
self-pin is committed in the corpus: a commit cannot contain its own object ID.
The consumer records the real commit and digest only after the fixture commit
exists and has been reviewed. A changed corpus needs an explicit consumer lock
update; branch names, moving tags and regeneration during tests are insufficient.
Integrity PASS is not protocol or consumer conformance.

Additional vectors must bind negative cases to nearby valid controls, expected exact
codes, permitted audit changes and retained-state invariants. Fixed byte hashes
and signature expectations need independent review. Consumer codecs and the
server must independently exercise the same data. Such integration remains open.

Only byte/schema/signature properties are exercised. No service, registrar
admission, registry checkpoint admission or consumer deployment is qualified.
