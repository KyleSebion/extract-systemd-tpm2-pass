#!/bin/bash -e
apt -y install xxd jq tpm2-tools &> /dev/null
luks=/dev/disk/by-partlabel/r
json=$(for i in {0..31}; do cryptsetup token export --token-id "$i" "$luks" 2>/dev/null; done | jq -c 'select(.type=="systemd-tpm2")')
blob=$(echo "$json" | jq -r '.["tpm2-blob"]' | base64 -d | xxd -p | tr -d ' \n')
alg=$(echo "$json" | jq -r '.["tpm2-primary-alg"]')
szsz=4 path=(na private.obj public.obj) offs=(0 0 0) sz=(0 0 0)
declare -A pathHex=()
for ((i = 1; i < "${#path[@]}"; ++i)); do
  offs[i]="${sz[i-1]}"
  sz[i]=$((szsz + 2 * 0x${blob:offs[i]:szsz}))
  pathHex+=("${path[i]}" "${blob:offs[i]:sz[i]}")
done
d=$(mktemp -d)
pushd "$d" &> /dev/null
for p in "${!pathHex[@]}"; do echo "${pathHex[$p]}" | xxd -r -p > "$p"; done
tpm2_createprimary -C o -c prim.ctx -g sha256 -G "$alg" -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth' > /dev/null
tpm2_load -C prim.ctx -c key.ctx -u public.obj -r private.obj > /dev/null
tpm2_startauthsession --policy-session -c prim.ctx -S pol.ctx
tpm2_policypcr -S pol.ctx -l sha256:7 > /dev/null
luksPass=$(tpm2_unseal -p session:pol.ctx -c key.ctx | base64)
tpm2_flushcontext pol.ctx
popd &> /dev/null
rm -r "$d"
test -n "$luksPass" && echo "LUKS password for '$luks' based on the systemd-tpm2 tpm2-blob: $luksPass"
