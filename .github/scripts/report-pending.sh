#!/usr/bin/env bash
# Discover documentation specifications only; never execute or qualify bodies.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python3 - "$script_dir" <<'PY'
from pathlib import Path
import re
import sys

scripts = Path(sys.argv[1])
root = scripts.parent.parent


def fail(message):
    sys.exit(message)


def entries(name):
    return [line.strip() for line in (scripts / name).read_text().splitlines()
            if line.strip() and not line.lstrip().startswith('#')]


inventories = entries('pending-inventories.txt')
if not inventories:
    fail('No PENDING inventories configured')
rows = {}
report = []
for inventory in inventories:
    path, pattern = inventory.split('|')
    source = root / path
    if not source.is_file():
        fail(f'Missing PENDING inventory: {path}')
    count = 0
    for line in source.read_text().splitlines():
        cells = [cell.strip() for cell in line.strip().strip('|').split('|')]
        if len(cells) < 2 or cells[1] != 'PENDING':
            continue
        if len(cells) != 3 or not re.fullmatch(pattern, cells[0]) or not cells[2]:
            fail(f'Malformed PENDING row in {path}')
        identity = f'{path} {cells[0]}'
        if identity in rows:
            fail(f'Duplicate PENDING row: {identity}')
        rows[identity] = True
        count += 1
        report.append(f'PENDING specification: {cells[0]} ({path}) requires '
                      f'{cells[2]}; not executable or qualified.')
    if count == 0:
        fail(f'No PENDING rows discovered in {path}')

# An independently maintained lower bound catches removed rows. Discovery,
# rather than this baseline, supplies the report so future rows appear too.
expected = entries('pending-rows.txt')
if not expected:
    fail('No expected PENDING rows configured')
for identity in expected:
    if identity not in rows:
        fail(f'Missing expected PENDING row: {identity}')

# No partial successful report escapes a failed inventory or lower-bound check.
print('\n'.join(report))
PY
