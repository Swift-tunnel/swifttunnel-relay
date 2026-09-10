#!/usr/bin/env bash
# No network or root: inject downloads and a failed final publish.
set -euo pipefail
script="$(cd -- "$(dirname -- "$0")/.." && pwd)/update-dest-allowlist.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
curl() {
    case "${*: -1}" in
        *AS22697) printf '{"prefix":"128.116.0.0/17"}' ;;
        *AS11281) printf '{"prefix":"141.193.3.0/24"}' ;;
        *) for ((i=0; i<50; i++)); do printf '"13.0.%s.0/24"\n' "$i"; done ;;
    esac
}
mv() {
    if [[ ${FAIL_PUBLISH:-0} == 1 ]]; then return 1; fi
    command mv "$@"
}
export -f curl mv
out="$work/list.txt"
printf 'old complete list\n' > "$out"
cp "$out" "$work/old.txt"
if FAIL_PUBLISH=1 bash "$script" "$out" >/dev/null; then
    echo 'expected failed publish' >&2
    exit 1
fi
cmp "$out" "$work/old.txt"
bash "$script" "$out" >/dev/null
grep -qx '128.116.0.0/17' "$out"
grep -qx '141.193.3.0/24' "$out"
[[ $(grep -c '^tcp ' "$out") == 50 ]]
[[ $(find "$work" -name '.dest-allowlist.*' | wc -l) == 0 ]]
echo 'allowlist publish tests passed'
