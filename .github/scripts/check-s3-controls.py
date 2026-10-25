#!/usr/bin/env python3
"""Bounded S3 mutations in private Go overlays; never edit checkout sources.

Each expected-red command must reach a specific test assertion. A compiler,
setup failure or timeout is a surviving control, never a killed mutant.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def replace(source, old, new):
    if source.count(old) != 1:
        raise RuntimeError("mutation site is not unique")
    return source.replace(old, new)


def change(path, old, new):
    return (path, old, new)


CAS = "TestCASRejectsGapAndConcurrentLoser"
RETRY = "TestOccupiedPositionRequiresExactBytesAndPredecessor"
BARRIER = "TestPreparedReceiptCannotEscapeBarriers"
AUDIT = "TestAuditFailureClosesAdmissionWithoutRecursion"
ADMIN = "TestAdminActivationIsAtomicWithHistory"
RESERVE = "TestStorageReserveAndRetentionFailClosed"
mutants = [
    ("M03_SKIP_HEAD_CAS", CAS, "CAS expected predecessor", [change("service/append.go", "if expected.Seq != headSeq || expected.Hash != headHash || seq != headSeq+1 || body[\"prev_hash\"] != headHash {", "if seq != headSeq+1 || body[\"prev_hash\"] != headHash {")]),
    ("M03_RETRY_BY_DIGEST_ONLY", RETRY, "digest equality cannot replace exact bytes", [change("service/append.go", "return digestEqual && bytes.Equal(original, line)", "return digestEqual && bytes.Equal(original, original)")]),
    ("M03_RETURN_PREPARED_RECEIPT", BARRIER, "external barrier holds receipt", [change("service/barrier.go", "var custody []byte", "return line, nil\n\tvar custody []byte")]),
    ("M03_SKIP_DIRECTORY_SYNC", BARRIER, "full barrier order", [change("store/transaction.go", "if e = d.calls.SyncDir(d.dir); e != nil {", "if false {")]),
    ("M03_RENAME_BEFORE_SYNC", BARRIER, "full barrier order", [change("store/transaction.go", "if e = d.calls.Sync(f); e != nil {", "if e = d.calls.Rename(d.dir, temp, name, replace); e != nil { return wire.Refuse(\"storage_unavailable\") }\n\tif e = d.calls.Sync(f); e != nil {"), change("store/transaction.go", "if e = d.calls.Rename(d.dir, temp, name, replace); e != nil {\n\t\treturn wire.Refuse(\"storage_unavailable\")\n\t}", "// moved rename before sync")]),
    ("M03_ACTIVATE_KEY_BEFORE_CONTROL_ACK", ADMIN, "new key activated before control ack", [change("service/admin.go", "prevReceipt := wire.ZeroHash", "s.state.Witness = next.Witness\n\tprevReceipt := wire.ZeroHash")]),
    ("M03_RELEASE_WITHOUT_AUDIT", AUDIT, "retry requires durable audit", [change("service/append.go", "_, e = s.commit(ctx, s.state, store.Manifest{Chain: \"audits\"}, nil, s.auditFields(peer, stream, \"retry\", id, old.Record, \"success\", \"\"), nil)", "e = nil")]),
    ("M03_DELETE_HISTORY_ON_FULL", RESERVE, "full history must not be deleted", [change("service/barrier.go", "e = wire.Refuse(\"storage_unavailable\")\n\t}\n\tobjects = append", "s.state.Entries = nil\n\t\te = wire.Refuse(\"storage_unavailable\")\n\t}\n\tobjects = append")]),
    ("M03_LOCAL_HASH_ONLY", RESERVE, "local hash alone cannot accept rollback", [change("service/barrier.go", "if e := s.checkIndependent(ctx); e != nil {", "if e := error(nil); e != nil {")]),
    ("M03_RETRY_NEW_RECEIPT", RETRY, "retry creates no new receipt", [change("service/append.go", "// Exact retry is an audit-only transaction.", "_, _ = evidence.NewReceipt(record, binding, old.Witness, old.Control, s.signers[old.Witness.Public])\n\t\t// Exact retry is an audit-only transaction.")]),
    ("M03_AUDIT_APPEND_RECURSION", AUDIT, "audit append recursion denied", [change("service/barrier.go", "if !s.active.CompareAndSwap(false, true) {", "if false && !s.active.CompareAndSwap(false, true) {"), change("service/barrier.go", "s.disk == nil || s.pending || s.held || s.stopped.Load()", "s.disk == nil || s.held || s.stopped.Load()")]),
]

# Valid control first; the source and test identities match every overlay.
base = ["go", "test", "-mod=readonly", "./service", "-run", "^(" + "|".join([CAS, RETRY, BARRIER, AUDIT, ADMIN, RESERVE]) + ")$", "-count=1", "-timeout=90s", "-v"]
result = subprocess.run(base, cwd=ROOT, capture_output=True, text=True, timeout=120)
print(json.dumps({"control": "unchanged", "command": base, "exit": result.returncode}), flush=True)
if result.returncode:
    print(result.stdout + result.stderr)
    raise SystemExit(1)
with tempfile.TemporaryDirectory(prefix="s3-controls-") as scratch:
    for name, test, assertion, edits in mutants:
        directory = Path(scratch) / name
        directory.mkdir()
        sources = {}
        for path, old, new in edits:
            sources[path] = replace(sources.get(path, (ROOT / path).read_text()), old, new)
        overlay = {"Replace": {}}
        for j, (path, source) in enumerate(sources.items()):
            destination = directory / (str(j) + ".go")
            destination.write_text(source)
            overlay["Replace"][str(ROOT / path)] = str(destination)
        overlay_path = directory / "overlay.json"
        overlay_path.write_text(json.dumps(overlay))
        command = ["go", "test", "-mod=readonly", "-overlay=" + str(overlay_path), "./service", "-run", "^" + test + "$", "-count=1", "-timeout=30s", "-v"]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=45)
        output = result.stdout + result.stderr
        killed = result.returncode == 1 and assertion in output and "--- FAIL: " + test in output and "[build failed]" not in output and "panic: test timed out" not in output
        print(json.dumps({"mutant": name, "test": test, "assertion": assertion, "exit": result.returncode, "killed": killed, "command": command}), flush=True)
        print(output, end="", flush=True)
        if not killed:
            raise SystemExit("SURVIVOR: " + name)
