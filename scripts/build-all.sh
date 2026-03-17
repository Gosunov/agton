set -euo pipefail
projects=(ton jetton wallet dedust nft)
for p in "${projects[@]}"; do
  rm -rf "$p/dist" "$p/build" "$p/*.egg-info"
  (cd "$p" && python3 -m build)
done
