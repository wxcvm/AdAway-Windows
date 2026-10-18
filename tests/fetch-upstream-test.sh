#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin" "$scratch/repo"
cp "$root/fetch-upstream.sh" "$scratch/repo/"
cp "$root/fetch-core-contract.sh" "$scratch/repo/"
export ADBLOCK_TEST_EXPECTED_PIN=$(sed -n 's/^PIN="\([a-f0-9]*\)"/\1/p' "$root/fetch-upstream.sh")
test "${#ADBLOCK_TEST_EXPECTED_PIN}" -eq 40
export ADBLOCK_TEST_CONTRACT_PIN=$(sed -n 's/^PIN="\([a-f0-9]*\)"/\1/p' "$root/fetch-core-contract.sh")
test "${#ADBLOCK_TEST_CONTRACT_PIN}" -eq 40
cat > "$scratch/bin/git" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = '-C' ]
directory="$2"; shift 2
case "$1" in
 init|remote) ;;
 fetch)
  [ "$2" = '--depth' ] && [ "$3" = 1 ] && [ "$4" = origin ]
  [ "$5" = "$ADBLOCK_TEST_EXPECTED_PIN" ] || [ "$5" = "$ADBLOCK_TEST_CONTRACT_PIN" ]
  printf '%s\n' "$5" > "$directory/.fetch-pin" ;;
 rev-parse) cat "$directory/.fetch-pin" ;;
 show)
  case "$2" in
   FETCH_HEAD:webserver/jni/traffic_core_contract.h|FETCH_HEAD:webserver/jni/traffic_core_contract_test.c|FETCH_HEAD:webserver/jni/traffic_core_vectors.txt|FETCH_HEAD:webserver/jni/traffic_core_contract.schema.json|FETCH_HEAD:webserver/jni/rule_norm.h|FETCH_HEAD:webserver/jni/rule_norm_test.c|FETCH_HEAD:webserver/jni/rule_vectors.txt|FETCH_HEAD:webserver/jni/domain_rule_snapshot.h|FETCH_HEAD:webserver/jni/domain_allow_snapshot.h|FETCH_HEAD:webserver/jni/block_rule_snapshot.h|FETCH_HEAD:webserver/jni/subscription_import.h|FETCH_HEAD:webserver/jni/domain_rule_snapshot_test.c|FETCH_HEAD:webserver/jni/block_rule_snapshot_test.c|FETCH_HEAD:webserver/jni/source_loader_vectors.txt|FETCH_HEAD:webserver/jni/typed_rule_record.h|FETCH_HEAD:webserver/jni/typed_rule_snapshot_test.c|FETCH_HEAD:webserver/jni/typed_rule_vectors.tsv)
    printf 'fixture %s\n' "$2" ;;
   *) exit 98 ;;
  esac ;;
 checkout)
  mkdir -p "$directory/webserver/jni/mongoose" "$directory/app/src/main/assets"
  printf 'core\n' > "$directory/webserver/jni/webserver.c"
  printf 'mongoose\n' > "$directory/webserver/jni/mongoose/mongoose.c"
  printf 'test\n' > "$directory/app/src/main/assets/test.html" ;;
 *) exit 99 ;;
esac
MOCK
chmod +x "$scratch/bin/git"
export PATH="$scratch/bin:$PATH"
cd "$scratch/repo"
bash fetch-upstream.sh
bash fetch-upstream.sh
printf 'local edit\n' >> jni/webserver.c
if bash fetch-upstream.sh; then echo 'modified cache was accepted' >&2; exit 1; fi
test "$(tail -1 jni/webserver.c)" = 'local edit'
rm .adblock-upstream-manifest.json
if bash fetch-upstream.sh; then echo 'unproven cache was accepted' >&2; exit 1; fi
test "$(tail -1 jni/webserver.c)" = 'local edit'
bash fetch-core-contract.sh
bash fetch-core-contract.sh
printf 'local contract edit\n' >> shared-contract/traffic_core_contract.h
if bash fetch-core-contract.sh; then echo 'modified contract was accepted' >&2; exit 1; fi
test "$(tail -1 shared-contract/traffic_core_contract.h)" = 'local contract edit'
rm shared-contract/manifest.json
if bash fetch-core-contract.sh; then echo 'unproven contract was accepted' >&2; exit 1; fi
test "$(tail -1 shared-contract/traffic_core_contract.h)" = 'local contract edit'
echo 'Pinned source fetch: exact SHA, repeatability, tampering and preservation passed'
