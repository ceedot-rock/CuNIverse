#!/usr/bin/env bash
#
# tests/test-verify.sh — exercise verify.sh against a scratch RFC 6962 log.
#
# Self-contained: builds the test log in a temp dir with python3
# (same Merkle semantics the publisher gets from ctlog), then runs:
#   1. happy path (two receipts)              -> VERIFIED
#   2. receipt with one flipped byte           -> TAMPERED: BAD_SIGNATURE
#   3. receipt with one flipped signature nibble -> TAMPERED: BAD_SIGNATURE
#   4. proof with swapped siblings            -> TAMPERED: PROOF_MISMATCH
#   5. valid receipt never logged              -> TAMPERED: NOT_IN_LOG
#   6. latest.json root tampered               -> TAMPERED: ROOT_MISMATCH
#   7. malformed JSON receipt                  -> TAMPERED: BAD_RECEIPT
#   8. receipt missing signature fields        -> TAMPERED: BAD_RECEIPT
#   9. missing PATH (no python3/openssl)       -> TAMPERED: MISSING_DEPS
#  10. nonexistent receipt file                -> TAMPERED: BAD_RECEIPT
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFY="$REPO/verify.sh"
FIX="$REPO/fixtures"

pass=0
fail=0
check() { # check <desc> <want_output> <want_exit> -- <cmd...>
    local desc="$1" want_out="$2" want_code="$3"
    shift 3
    [[ "${1:-}" == "--" ]] && shift
    set +e
    local got_out
    got_out="$("$@")"
    local got_code=$?
    set -e
    if [[ "$got_out" == "$want_out" && "$got_code" == "$want_code" ]]; then
        pass=$((pass + 1))
        echo "ok   - $desc"
    else
        fail=$((fail + 1))
        echo "FAIL - $desc"
        echo "       want: [$want_out] exit $want_code"
        echo "       got:  [$got_out] exit $got_code"
    fi
}

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
LOG="$T/testlog"

# Build a 3-leaf test log [r1, r2, r1] with RFC 6962 semantics, using the
# ctlog promotion convention: a promoted (odd) node records its OWN hash as
# the stand-in sibling; the verifier treats sibling == running hash as
# "promoted, hash unchanged".
python3 - "$LOG" "$FIX/sample-receipt.json" "$FIX/sample-receipt-2.json" \
    "$FIX/sample-receipt.json" <<'PYEOF'
import hashlib, json, os, sys
from datetime import datetime, timezone
def H(b): return hashlib.sha256(b).digest()
dest = sys.argv[1]
leaves = [open(p, "rb").read() for p in sys.argv[2:]]
for d in ("leaves", "roots", "proofs"):
    os.makedirs(os.path.join(dest, "log", d), exist_ok=True)
for i, r in enumerate(leaves):
    open(os.path.join(dest, "log", "leaves", "%08d.json" % i), "wb").write(r)
lh = [H(b"\x00" + l) for l in leaves]
n = len(lh)
proofs = [[] for _ in range(n)]
level = lh
pos = list(range(n))
while len(level) > 1:
    for k, p in enumerate(pos):
        if p % 2 == 1:
            proofs[k].append(level[p - 1].hex())   # sibling on the left
        elif p + 1 < len(level):
            proofs[k].append(level[p + 1].hex())   # sibling on the right
        else:
            proofs[k].append(level[p].hex())       # promoted: stand-in
    nxt = []
    i = 0
    while i < len(level):
        if i + 1 < len(level):
            nxt.append(H(b"\x01" + level[i] + level[i + 1]))
            i += 2
        else:
            nxt.append(level[i])                  # promoted unchanged
            i += 1
    level = nxt
    pos = [p // 2 for p in pos]
root = level[0] if level else b"\x00" * 32
hour = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:00:00Z")
rdoc = {"hour": hour, "root": root.hex(), "leaf_count": len(leaves)}
open(os.path.join(dest, "log", "roots", hour + ".json"), "w").write(json.dumps(rdoc, indent=2) + "\n")
open(os.path.join(dest, "log", "roots", "latest.json"), "w").write(json.dumps(rdoc, indent=2) + "\n")
for i, sibs in enumerate(proofs):
    p = {"leaf_index": i, "leaf_count": len(leaves), "siblings": sibs,
         "root": root.hex(), "hour": hour}
    open(os.path.join(dest, "log", "proofs", "%08d.json" % i), "w").write(json.dumps(p, indent=2) + "\n")
print("test log ready", file=sys.stderr)
PYEOF

R1="$FIX/sample-receipt.json"
R2="$FIX/sample-receipt-2.json"
R3="$FIX/sample-receipt-3.json"  # valid signature, never logged

# 1. happy path
check "happy path receipt 1" "VERIFIED" 0 -- "$VERIFY" "$R1" --log-dir "$LOG"
check "happy path receipt 2" "VERIFIED" 0 -- "$VERIFY" "$R2" --log-dir "$LOG"

# 2. one flipped byte inside the signed body (JSON stays valid)
python3 - "$R1" "$T/tampered.json" <<'PYEOF'
import sys
raw = bytearray(open(sys.argv[1], "rb").read())
i = raw.find(b"exactness: PASS")
assert i > 0
raw[i + 12] = ord("X")  # 'P' -> 'X' inside the summary string
open(sys.argv[2], "wb").write(bytes(raw))
PYEOF
check "flipped body byte" "TAMPERED: BAD_SIGNATURE" 1 -- \
    "$VERIFY" "$T/tampered.json" --log-dir "$LOG"

# 3. one flipped nibble inside the signature hex (still valid hex)
python3 - "$R1" "$T/tamperedsig.json" <<'PYEOF'
import sys
t = open(sys.argv[1]).read()
marker = '"signature": "'
i = t.find(marker) + len(marker)
c = t[i]
t = t[:i] + ("0" if c != "0" else "1") + t[i + 1:]
open(sys.argv[2], "w").write(t)
PYEOF
check "flipped signature nibble" "TAMPERED: BAD_SIGNATURE" 1 -- \
    "$VERIFY" "$T/tamperedsig.json" --log-dir "$LOG"

# 4. proof with swapped siblings (leaf 0 has 2 siblings in a 3-leaf tree)
LOG4="$T/testlog4"
cp -r "$LOG" "$LOG4"
python3 - "$LOG4/log/proofs/00000000.json" <<'PYEOF'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
assert len(d["siblings"]) == 2, "need 2 siblings to swap"
d["siblings"] = d["siblings"][::-1]
json.dump(d, open(p, "w"), indent=2)
PYEOF
check "swapped proof siblings" "TAMPERED: PROOF_MISMATCH" 1 -- \
    "$VERIFY" "$R1" --log-dir "$LOG4"

# 5. valid receipt, never logged
check "receipt not in log" "TAMPERED: NOT_IN_LOG" 1 -- \
    "$VERIFY" "$R3" --log-dir "$LOG"

# 6. latest.json root tampered
LOG6="$T/testlog6"
cp -r "$LOG" "$LOG6"
python3 - "$LOG6/log/roots/latest.json" <<'PYEOF'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["root"] = "ff" * 32
json.dump(d, open(p, "w"), indent=2)
PYEOF
check "tampered latest root" "TAMPERED: ROOT_MISMATCH" 1 -- \
    "$VERIFY" "$R1" --log-dir "$LOG6"

# 7. malformed JSON
echo "this is not json{" > "$T/bad.json"
check "malformed receipt" "TAMPERED: BAD_RECEIPT" 1 -- \
    "$VERIFY" "$T/bad.json" --log-dir "$LOG"

# 8. receipt missing the signature fields
python3 - "$R1" "$T/nosig.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
del d["signer_pubkey"]
del d["signature"]
json.dump(d, open(sys.argv[2], "w"))
PYEOF
check "receipt without signature fields" "TAMPERED: BAD_RECEIPT" 1 -- \
    "$VERIFY" "$T/nosig.json" --log-dir "$LOG"

# 9. missing dependencies (empty PATH; invoke bash explicitly since the
#    shebang's `env` lookup needs PATH too)
check "missing deps" "TAMPERED: MISSING_DEPS" 1 -- \
    env -i PATH=/nonexistent-verify-test /usr/bin/bash "$VERIFY" "$R1" --log-dir "$LOG"

# 10. nonexistent receipt file
check "nonexistent receipt" "TAMPERED: BAD_RECEIPT" 1 -- \
    "$VERIFY" "$T/does-not-exist.json" --log-dir "$LOG"

echo
echo "pass=$pass fail=$fail"
[[ "$fail" -eq 0 ]]
