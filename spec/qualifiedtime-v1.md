# WC1 inactive qualified-time adapter, version 1

This implementation follows the accepted [window profiles](witness-qt2c-profile.md).
It supplies structural codecs, four consuming adapters and local S3 use retention.
It does not qualify a provider, native endpoint, deadlines, custody or either OS.
Production constructors select broker `ClosedWitness` and `ClosedOriginalReader`,
accept no dependency injection and return `handoff_unqualified` on consumption,
including when the fixture build tag is set. No wall-clock fallback exists.
The unserved service constructs these closed windows; its old synthetic S3
coordinator paths are not promoted to qualified G16 paths. Serving remains closed.

## Operation and admission

`internal/qualifiedtime` has distinct P/R/X/TLS adapters. P/R/X use the
length-prefixed `qualified-time/consumer-operation/1` recipe over their respective
profile and CCJ-1 `witness-window-intent/1` body. The body binds service/lineage,
original identity, principal/method/exact argument digest/signing purpose,
authority generation/incarnation, connection, fixed phase/slot, exact native
root/record/control/audit/policy/candidate/confirmation/reservation, live epoch,
unused revision and original boot/domain/deadline/budget mapping. Frozen endpoint
bytes are committed by digest before preparation. Neither H nor m nor Run enters
that operation digest. Run and Epoch remain independently compared broker fields.
X also binds positive commit/send bounds whose checked sum fits its original f.
No numeric production bound is installed.

TLS pin/role/chain/CRL verification remains an independently staged S2 prerequisite.
TLS keeps the exact existing `state-witness-tls:1` body and digest. It gains no
wrapper or new member. The receiver separately compares the full independently
protected native snapshot, including the full S3 predecessor, live epoch and
unused scalar generation under admitted G/L before m. P/R/X additionally bind
that snapshot in their operation body. The full snapshot is retained with every
use regardless of the operation-body form; it is never cast into Revision.

All parsing, ownership copies, original reconstruction and codec mapping precede
terminal admission. The final chain is G/S/A/L for P/R/X and G/L for TLS;
production windows share their local gates. The owning S3 admission retains L
through selection, one `FinalCapture`, pure `VerifyWindow`, durable burn and the
endpoint. The native snapshot and exact unused generation are checked before m.
The receiver refuses a second capture or consume. Every final-chain exit retires
the transient preparation, including a failed check; this H-indexed retirement
cache is not the durable use key. Its bounded capacity refuses on exhaustion.
Stop only sets atomics and does not wait for gates or dependencies.

No provider, original reader, signer, archive or custodian work belongs under
terminal gates. The production package contains no accepting endpoint/clock
runtime constructor. Tagged `_test.go` files alone construct deterministic clock
and effect models and use the broker's `timeconftest` private preparations.
Their time budgets and synthetic enforcement are test controls, not WC1 limits.
A future runtime must enforce the original deadline/current epoch through the
complete native effect and all durability, without another clock/provider call
in the adapter. Independent lifetime exclusion/live invalidation remain absent.

## Protected mapping and structural bundle

The only protected mapping is `witness-transition-map:1`:
`WC1TimeUse/1` ↔ `WC1TimeUse:1`. Expectation construction, Encode and Decode all
require that exact pair and version, and metadata must match the independently
expected operation, challenge, run, window, deadline and budget. Literal slash,
generic replacement, unknown entry, version drift or mismatch refuses. Structural
decode and matching copied originals do not authenticate a reader or witness and
cannot construct `PreparedHandoff`. A candidate's exact H commitment must match
the already copied/checked envelope before any burn.

## S3 owning use transaction

The internal S3 manifest has a closed version 2 extension, `time_use_hash`, in
segment, prepare, outcome and root. Version 1 bytes are unchanged when that field
is absent. This is local S3 metadata, not a new closed WS member, chain or receipt.
The hash selects a `WC1TimeUse/1` object in the same immutable-object namespace and
root ancestry. Every phase must select the same use object. Ordinary service
transactions inherit the current use hash; they cannot erase burns by restoring
an older service index. Reopen walks retained roots and checks monotone use
transitions as well as exact object/phase links. Independent rollback authority
remains PENDING; coherent local history is not evidence of current custody.

Before time preparation, the protected operation/connection owner allocates
unused slots against an exact current root. Each key is the stable lineage,
original operation or connection attempt identity, fixed P/R/X/TLS phase and
slot 1. A new slot starts at generation 0; its one burn advances to 1. H, run,
challenge, current process incarnation and operation digest never allocate a
replacement slot. Allocation rejects duplicates and exhausted capacity; there
is no public bootstrap/genesis/recovery or automatic migration authority.

`unused -> burned -> committed|held` retains exact native identity, full snapshot,
broker expected fields, run/epoch, H envelope and complete original copies.
Burned never returns to unused. Unknown local persistence fences the store;
recovery presents an incomplete burn as held, with no dispatch method. Exact
committed outcomes may be read as status only. No tombstone deletion or revision
wrap is permitted. Up to 64 slots fit one bounded 1 MiB table; exhaustion refuses
rather than dropping history. Existing 1 MiB segment, 64 KiB journal and 4096-byte
root caps still apply. Envelopes are at most 128 KiB, native retained intent
64 KiB, frozen endpoint 64 KiB and outcome 128 KiB. Complete original retention
must also fit the stricter S3 table bound; it is never truncated.

Use commits reuse immutable object writes, file sync, checked close, no-replace
install, parent sync, prepare/outcome journals and atomic root publication. Full
retained inventory and exact use/root readback are checked before returning.
The service index, frozen audit and closed custody tuple are unchanged. Use
persistence is not recursively audited and does not form a separately
acknowledged ledger. Exact independent use/root custody and hard capacity/device
qualification are still required before activation.

For P/R, the burn precedes the local ActProtocol endpoint and its committed
outcome. A failed endpoint retains held use. TLS commits durable peer-admission
use before its modeled application-admission effect. X commits
`XReleaseCommitted`, binding the original key, exact intent/H/original references,
root, epoch, connection and frozen frame before its sole bounded send attempt.
A failed or late send keeps committed release authority and uncertain delivery;
it never enables a resend. All authoritative recovery bindings precede the send.
A later delivery note has no authority-writing method in the adapter; isolated
fixture maintenance failures cannot change the retained use entry.

[Tests and remaining qualification](qualifiedtime-tests.md) bound the evidence.
No native pause, suspend, power-loss, replacement-executor or macOS qualification
is supplied by these local/injected tests. G07/G10 and all other activation gates
remain closed.

The private runtime enforcement contract encloses the entire ActProtocol
endpoint callback, including its durable authority commit. Enforcing only the
separable send/application effect would allow a late X/TLS authority commit.
A failure before that commit leaves the burn held; a delivery failure after a
timely commit preserves the committed authority and cannot authorize another
send. Tagged deterministic enforcement models these two pause positions; native
enforcement through the complete callback remains PENDING.
