#!/usr/bin/env bash
# Claims: discovery includes new rows, deletion/empty discovery fail closed,
# and malformed/missing inputs produce no partial successful PENDING report.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
control_dir="$(mktemp -d)"
chmod 0700 "$control_dir"
trap 'rm -rf -- "$control_dir"' EXIT
mkdir -p "$control_dir/valid/.github/scripts" "$control_dir/valid/spec"
cp "$script_dir/"{report-pending.sh,pending-inventories.txt,pending-rows.txt} "$control_dir/valid/.github/scripts/"
expected=0
while read -r path name; do
  if test -z "$path" || [[ "$path" = \#* ]]; then continue; fi
  expected=$((expected + 1))
  printf '| %s | PENDING | external qualification |\n' "$name" >> "$control_dir/valid/$path"
done < "$script_dir/pending-rows.txt"
printf '| TestPendingFuture | PENDING | future qualification |\n' >> "$control_dir/valid/spec/policy-tests.md"
(cd "$control_dir/valid" && bash .github/scripts/report-pending.sh) > "$control_dir/valid.out"
test "$(wc -l < "$control_dir/valid.out")" -eq "$((expected + 1))"
grep -F 'PENDING specification: TestPendingFuture (spec/policy-tests.md)' "$control_dir/valid.out"
printf '%s\n' 'PASS TestCIPendingDynamicDiscovery: new specification appears without baseline change'

for plant in missing-row empty-discovery missing-file empty-inventories empty-baseline malformed-row; do
  cp -R "$control_dir/valid" "$control_dir/$plant"
  target="$control_dir/$plant/spec/policy-tests.md"
  case "$plant" in
    missing-row)
      sed '/^| TestProvisionDurableConsentConsumedOnce |/d' "$target" > "$target.new"
      mv "$target.new" "$target"
      diagnostic='Missing expected PENDING row: spec/policy-tests.md TestProvisionDurableConsentConsumedOnce'
      claim=TestCIPendingMissingRow ;;
    empty-discovery)
      sed 's/| PENDING |/| QUALIFIED |/g' "$target" > "$target.new"
      mv "$target.new" "$target"
      diagnostic='No PENDING rows discovered in spec/policy-tests.md'
      claim=TestCIPendingEmptyDiscovery ;;
    missing-file)
      rm -- "$target"
      diagnostic='Missing PENDING inventory: spec/policy-tests.md'
      claim=TestCIPendingMissingFile ;;
    empty-inventories)
      : > "$control_dir/$plant/.github/scripts/pending-inventories.txt"
      diagnostic='No PENDING inventories configured'
      claim=TestCIPendingEmptyInventories ;;
    empty-baseline)
      : > "$control_dir/$plant/.github/scripts/pending-rows.txt"
      diagnostic='No expected PENDING rows configured'
      claim=TestCIPendingEmptyBaseline ;;
    malformed-row)
      printf '| Invalid specification | PENDING | qualification |\n' >> "$target"
      diagnostic='Malformed PENDING row in spec/policy-tests.md'
      claim=TestCIPendingMalformedRow ;;
  esac
  status=0
  (cd "$control_dir/$plant" && bash .github/scripts/report-pending.sh) > "$control_dir/$plant.out" 2> "$control_dir/$plant.err" || status=$?
  test "$status" -eq 1
  test ! -s "$control_dir/$plant.out"
  grep -Fx -- "$diagnostic" "$control_dir/$plant.err"
  printf 'PASS %s: plant=%s expected reporter exit=%s\n' "$claim" "$plant" "$status"
done
