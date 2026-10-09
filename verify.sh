#!/usr/bin/env bash
#
# verify.sh — verify a CuNi v0.10.0 signed receipt against the transparency log.
#
# Usage: verify.sh <receipt.json> [--log-dir <path>]
#   <receipt.json>  the signed receipt file to verify
#   --log-dir       repo root containing log/ (default: ./)
#
# Prints exactly one line:
#   VERIFIED                (exit 0)
#   TAMPERED: <reason>      (exit 1)
# Reasons: BAD_SIGNATURE, NOT_IN_LOG, PROOF_MISMATCH, ROOT_MISMATCH,
#          MISSING_DEPS, BAD_RECEIPT.
#
# Check order: receipt well-formedness, then Ed25519 signature (openssl),
# then log inclusion, then Merkle proof, then latest-root anchoring.
# No network access. Works on a local clone.
#
set -euo pipefail

usage() {
    echo "usage: verify.sh <receipt.json> [--log-dir <path>]" >&2
}

# (a) dependency check
for dep in python3 openssl; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        echo "TAMPERED: MISSING_DEPS"
        exit 1
    fi
done

# argument parsing
receipt=""
logdir="./"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --log-dir)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            logdir="$2"
            shift 2
            ;;
        --log-dir=*)
            logdir="${1#--log-dir=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "verify.sh: unknown option $1" >&2
            usage
            exit 2
            ;;
        *)
            if [[ -n "$receipt" ]]; then
                echo "verify.sh: only one receipt file expected" >&2
                usage
                exit 2
            fi
            receipt="$1"
            shift
            ;;
    esac
done
[[ -n "$receipt" ]] || { usage; exit 2; }
[[ -f "$receipt" ]] || { echo "TAMPERED: BAD_RECEIPT"; exit 1; }

tmpd="$(mktemp -d)"
trap 'rm -rf "$tmpd"' EXIT

# Python does: JSON parse + field checks, unsigned-bytes reconstruction,
# leaf-hash computation + leaf scan, proof load + root recomputation,
# latest-root comparison. It prints either "TAMPERED: <reason>" (fatal,
# receipt unusable) or two lines:
#   SIGCHECK <unsigned.bin> <sig.bin> <pubkey.pem>
#   CHECK <OK|NOT_IN_LOG|PROOF_MISMATCH|ROOT_MISMATCH>
out="$(CT_TMPD="$tmpd" python3 - "$receipt" "$logdir" <<'PYEOF'
import base64
import glob
import hashlib
import json
import os
import re
import sys

REQUIRED_FIELDS = ["path", "source_hash", "cuni_version", "exact",
                   "stdout_hash", "seats", "signer_pubkey", "signature"]

def fatal(reason):
    # Receipt itself is unusable; nothing further can be checked.
    print("TAMPERED: " + reason)
    sys.exit(0)

def unsigned_bytes(signed: bytes):
    """Strip the trailing signature block as TEXT.

    Mirrors ctlog::unsigned_bytes: the signed receipt ends with
        ,\\n  "signer_pubkey": "<64 hex>",\\n  "signature": "<128 hex>"
    followed by \\n} and then only newlines (from output capture).
    The unsigned form is everything before the block plus "\\n}\\n" —
    exactly the bytes cuni signed.
    """
    try:
        t = signed.decode("utf-8")
    except UnicodeDecodeError:
        return None
    marker = ',\n  "signer_pubkey": "'
    i = t.rfind(marker)
    if i < 0:
        return None
    tail = t[i + len(marker):]
    m = re.fullmatch(r'([0-9a-f]{64})",\n  "signature": "([0-9a-f]{128})"\n\}(\n*)', tail)
    if not m:
        return None
    return (t[:i] + "\n}\n").encode("utf-8"), bytes.fromhex(m.group(1)), bytes.fromhex(m.group(2))

def main():
    receipt_path, logdir = sys.argv[1], sys.argv[2]
    tmpd = os.environ["CT_TMPD"]
    try:
        raw = open(receipt_path, "rb").read()
    except OSError:
        fatal("BAD_RECEIPT")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        fatal("BAD_RECEIPT")
    if not isinstance(doc, dict):
        fatal("BAD_RECEIPT")
    for f in REQUIRED_FIELDS:
        if f not in doc:
            fatal("BAD_RECEIPT")
    if not re.fullmatch(r"[0-9a-f]{64}", str(doc["signer_pubkey"])):
        fatal("BAD_RECEIPT")
    if not re.fullmatch(r"[0-9a-f]{128}", str(doc["signature"])):
        fatal("BAD_RECEIPT")

    rec = unsigned_bytes(raw)
    if rec is None:
        fatal("BAD_RECEIPT")
    unsigned, pub_raw, sig_raw = rec

    # materialize files for the openssl step
    unsigned_p = os.path.join(tmpd, "unsigned.bin")
    sig_p = os.path.join(tmpd, "sig.bin")
    pub_p = os.path.join(tmpd, "pubkey.pem")
    open(unsigned_p, "wb").write(unsigned)
    open(sig_p, "wb").write(sig_raw)
    # Ed25519 SubjectPublicKeyInfo DER: 302a 3005 06032b6570 032100 || raw key
    der = bytes.fromhex("302a300506032b6570032100") + pub_raw
    b64 = base64.encodebytes(der).decode("ascii")
    open(pub_p, "w").write("-----BEGIN PUBLIC KEY-----\n" + b64 + "-----END PUBLIC KEY-----\n")

    check = "OK"
    # (c) leaf hash = SHA256(0x00 || exact receipt bytes); find seq
    leaf_hash = hashlib.sha256(b"\x00" + raw).hexdigest()
    seq = None
    leaf_files = sorted(glob.glob(os.path.join(logdir, "log", "leaves", "*.json")))
    for lf in leaf_files:
        try:
            h = hashlib.sha256(b"\x00" + open(lf, "rb").read()).hexdigest()
        except OSError:
            continue
        if h == leaf_hash:
            base = os.path.basename(lf)
            if re.fullmatch(r"[0-9]{8}\.json", base):
                seq = base[:-5]
                break
    if seq is None:
        check = "NOT_IN_LOG"
    else:
        # (d) load proof, recompute root from leaf + siblings
        proof_ok = False
        try:
            proof = json.load(open(os.path.join(logdir, "log", "proofs", seq + ".json")))
            if not isinstance(proof, dict):
                raise ValueError("proof not an object")
            leaf_index = proof["leaf_index"]
            leaf_count = proof["leaf_count"]
            siblings = proof["siblings"]
            proof_root = proof["root"]
            if int(seq) != leaf_index:
                raise ValueError("leaf_index mismatch")
            if not isinstance(siblings, list) or not all(
                    isinstance(s, str) and re.fullmatch(r"[0-9a-f]{64}", s) for s in siblings):
                raise ValueError("bad siblings")
            if not re.fullmatch(r"[0-9a-f]{64}", proof_root):
                raise ValueError("bad proof root")
            if leaf_count != len(leaf_files):
                raise ValueError("leaf_count mismatch")
            # Proof must carry exactly one sibling per tree level above the
            # leaves (mirrors ctlog::verify_inclusion).
            exp_len = 0
            m = leaf_count
            while m > 1:
                m = (m + 1) // 2
                exp_len += 1
            if len(siblings) != exp_len:
                raise ValueError("sibling count does not fit leaf_count")
            h = bytes.fromhex(leaf_hash)
            idx = leaf_index
            for s in siblings:  # siblings ordered leaf level -> root
                sib = bytes.fromhex(s)
                if sib == h:
                    pass  # promoted node: stand-in sibling, hash unchanged
                elif idx % 2 == 0:
                    h = hashlib.sha256(b"\x01" + h + sib).digest()
                else:
                    h = hashlib.sha256(b"\x01" + sib + h).digest()
                idx //= 2
            if h.hex() != proof_root:
                raise ValueError("recomputed root differs from proof root")
            proof_ok = True
        except (OSError, ValueError, KeyError, TypeError):
            check = "PROOF_MISMATCH"
        if proof_ok:
            try:
                latest = json.load(open(os.path.join(logdir, "log", "roots", "latest.json")))
                latest_root = latest["root"]
            except (OSError, ValueError, KeyError, TypeError):
                check = "ROOT_MISMATCH"
            else:
                if latest_root != proof_root:
                    check = "ROOT_MISMATCH"

    print("SIGCHECK %s %s %s" % (unsigned_p, sig_p, pub_p))
    print("CHECK " + check)

try:
    main()
except SystemExit:
    raise
except Exception as e:  # fail closed on anything unexpected
    print("py-error: %s" % e, file=sys.stderr)
    sys.exit(2)
PYEOF
)" || { echo "TAMPERED: BAD_RECEIPT"; exit 1; }

if [[ "$out" == TAMPERED:* ]]; then
    echo "$out"
    exit 1
fi

sig_line="$(printf '%s\n' "$out" | sed -n '1p')"
check_line="$(printf '%s\n' "$out" | sed -n '2p')"
if [[ "$sig_line" != SIGCHECK\ * ]] || [[ "$check_line" != CHECK\ * ]]; then
    echo "TAMPERED: BAD_RECEIPT"
    exit 1
fi

# (b) Ed25519 verification via openssl (Ed25519 raw keys, OpenSSL 3.x).
read -r _ unsigned_f sig_f pub_f <<<"$sig_line"
if ! openssl pkeyutl -verify -pubin -inkey "$pub_f" -rawin \
        -in "$unsigned_f" -sigfile "$sig_f" >/dev/null 2>&1; then
    echo "TAMPERED: BAD_SIGNATURE"
    exit 1
fi

check="${check_line#CHECK }"
if [[ "$check" != "OK" ]]; then
    echo "TAMPERED: $check"
    exit 1
fi

echo "VERIFIED"
exit 0
