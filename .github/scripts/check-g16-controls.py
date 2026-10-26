#!/usr/bin/env python3
"""WC1 virtual-time decision controls; real IO and unchanged deadline constants.

Tuple real-time qualification is selected separately, never by this hosted gate.

An unrelated setup/build failure or timeout is a survivor, never a killed plant.
Run with a protected private TMPDIR and the pinned Go modules already downloaded.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = "internal/qualifiedtime/adapter_linux.go"

def edit(old, new):
    return (old, new)

mutants = [
    ("G16_CAPTURE_BEFORE_ADMISSION", "TestWindowTimelyEndpoint", "timely endpoint must commit once", [
        edit("e.g.Lock()", "early, earlyErr := e.runtime.clock.Capture()\n e.g.Lock()"),
        edit("m, err := session.capture()", "m, err := early, earlyErr; session.read = true")]),
    ("G16_SECOND_READ", "TestWindowTimelyEndpoint", "timely endpoint must commit once", [
        edit("candidate, err := timeconf.VerifyWindow", "_, err = session.capture(); if err != nil { return err }; candidate, err := timeconf.VerifyWindow")]),
    ("G16_BURN_AFTER_ACT", "TestWindowTimelyEndpoint", "durable burn must precede act", [
        edit('if err := s.admitted.Burn(u); err != nil {\n\t\treturn err\n\t}\n\treturn act.Act()', 'if err := act.Act(); err != nil { return err }; return s.admitted.Burn(u)')]),
    ("G16_X_SEND_BEFORE_COMMIT", "TestXPostSendAccountingFailure", "durable authority must precede every byte", [
        edit('if err = s.admitted.Finish("committed", out); err != nil {', 'if err = s.runtime.effect.Act(); err != nil { return err }; if err = s.admitted.Finish("committed", out); err != nil {'),
        edit('return s.runtime.effect.Act()', 'return nil')]),
    ("G16_LATE_AUTHORITY_COMMIT", "TestWindowLateCommitForbidden", "late authority commit must be prevented", [
        edit('s.runtime.effect.Execute(endpointProtocol{s})', 's.localEndpoint()')]),
    ("G16_H_AS_KEY", "TestWindowStableKey", "stable original slot must accept independently of H", [
        edit('admitted, err := e.disk.AdmitTimeUse', 'i.Original = commitment[len("sha256:"):len("sha256:")+32]\n admitted, err := e.disk.AdmitTimeUse')]),
    ("G16_EPOCH_EQUALS_RUN", "TestWindowNativeReadSetAndEpoch", "epoch must remain distinct from run", [
        edit('Run: i.Run, Epoch: i.Snapshot.Epoch,', 'Run: i.Run, Epoch: i.Run,')]),
    ("G16_GENERIC_SLASH_MAPPING", "TestClosedTransitionMapping", "generic slash/version mapping accepted", [
        edit('"strconv"', '"strconv"\n "strings"'),
        edit('mapping != MappingVersion || native != NativeTransition || enrolled != EnrolledTransition', 'mapping != MappingVersion || strings.ReplaceAll(native, "/", ":") != enrolled')]),
    ("G16_NULL_TABLE_HISTORY_SKIP", "TestTimeUseReopenRejectsDeletedTable", "deleted retained burns must refuse on reopen", [
        edit('haveNewerUses && !validTimeUseStep(uses, newerUses)', 'haveNewerUses && newerUses != nil && !validTimeUseStep(uses, newerUses)')]),
    ("G16_PRODUCTION_FIXTURE_WITNESS", "TestProductionDependenciesClosed", "production fixture witness is forbidden", [
        edit('witness: timeconf.ClosedWitness{}', 'witness: &fixtureWitness{}')]),
]

base = ["go", "test", "-mod=readonly", "-tags=swarma_timeconf_fixture", "./internal/qualifiedtime", "-count=1", "-timeout=60s", "-v"]
result = subprocess.run(base, cwd=ROOT, capture_output=True, text=True, timeout=90)
print(json.dumps({"control":"unchanged", "command":base, "pid_owner":os.getpid(), "exit":result.returncode}), flush=True)
if result.returncode:
    print(result.stdout+result.stderr)
    raise SystemExit(1)
with tempfile.TemporaryDirectory(prefix="g16-controls-") as scratch:
    for name, test, assertion, edits in mutants:
        source_path = "store/transaction.go" if name=="G16_NULL_TABLE_HISTORY_SKIP" else SOURCE
        source=(ROOT/source_path).read_text()
        for old,new in edits:
            if source.count(old)!=1:
                raise RuntimeError("nonunique mutation site: "+name)
            source=source.replace(old,new)
        if name=="G16_PRODUCTION_FIXTURE_WITNESS":
            source += "\ntype fixtureWitness struct{}\nfunc (*fixtureWitness) Read(context.Context) (timeconf.WitnessHead,error) { return timeconf.WitnessHead{},nil }\nfunc (*fixtureWitness) CompareAndSwap(context.Context,timeconf.WitnessHead,timeconf.WitnessHead) error { return nil }\n"
        directory=Path(scratch)/name
        directory.mkdir()
        replacement=directory/"adapter_linux.go"
        replacement.write_text(source)
        overlay=directory/"overlay.json"
        overlay.write_text(json.dumps({"Replace":{str(ROOT/source_path):str(replacement)}}))
        command=["go","test","-mod=readonly","-tags=swarma_timeconf_fixture","-overlay="+str(overlay),"./store" if name=="G16_NULL_TABLE_HISTORY_SKIP" else "./internal/qualifiedtime","-run","^"+test+"$","-count=1","-timeout=30s","-v"]
        result=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=45)
        output=result.stdout+result.stderr
        killed=(result.returncode==1 and assertion in output and "--- FAIL: "+test in output and "[build failed]" not in output and "panic:" not in output)
        print(json.dumps({"mutant":name,"test":test,"assertion":assertion,"command":command,"exit":result.returncode,"killed":killed}),flush=True)
        print(output,end="",flush=True)
        if not killed:
            raise SystemExit("SURVIVOR: "+name)

# The lifecycle detector must reject both a passing child and an unrelated
# child failure. Neither is evidence that the deliberately stuck worker ran.
lifecycle_source = "internal/qualifiedtime/window_lifecycle_linux_test.go"
lifecycle_test = "TestWindowWorkerLifecycle/stuck-child"
lifecycle_assertion = "stuck worker must be detected in child"
for name, plant in [
    ("LIFECYCLE_CHILD_PASSES", 'if mode == "stuck" { return }\n\t'),
    ("LIFECYCLE_CHILD_WRONG_FAILURE", 'if mode == "stuck" { t.Fatal("unrelated lifecycle child failure") }\n\t'),
]:
    source = (ROOT / lifecycle_source).read_text()
    site = 'if mode != "fatal" && mode != "stuck" {'
    if source.count(site) != 1:
        raise RuntimeError("nonunique lifecycle control site: " + name)
    with tempfile.TemporaryDirectory(prefix="g16-lifecycle-") as scratch:
        replacement = Path(scratch) / "window_lifecycle_linux_test.go"
        replacement.write_text(source.replace(site, plant + site))
        overlay = Path(scratch) / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(ROOT / lifecycle_source): str(replacement)}}))
        command = ["go", "test", "-mod=readonly", "-tags=swarma_timeconf_fixture", "-overlay=" + str(overlay), "./internal/qualifiedtime", "-run", "^TestWindowWorkerLifecycle$/^stuck-child$", "-count=1", "-timeout=15s", "-v"]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20)
        output = result.stdout + result.stderr
        killed = result.returncode == 1 and lifecycle_assertion in output and "--- FAIL: " + lifecycle_test in output and "[build failed]" not in output and "panic:" not in output
        print(json.dumps({"lifecycle_control": name, "test": lifecycle_test, "assertion": lifecycle_assertion, "command": command, "exit": result.returncode, "killed": killed}), flush=True)
        print(output, end="", flush=True)
        if not killed:
            raise SystemExit("SURVIVOR: " + name)
