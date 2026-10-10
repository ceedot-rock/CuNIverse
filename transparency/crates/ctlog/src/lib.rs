//! `ctlog` — Merkle transparency-log core for CuNi signed receipts.
//!
//! Leaves are the exact bytes of CuNi signed receipt JSON files as produced
//! by `cuni check --sign` (CuNi v0.10.0). The tree hashes follow
//! [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) (Certificate
//! Transparency):
//!
//! * `leaf_hash = SHA-256(0x00 || leaf_bytes)`
//! * `node_hash = SHA-256(0x01 || left || right)`
//! * an odd node at any level is promoted unchanged
//!
//! Receipt signatures follow the CuNi rule: CuNi signs the exact UTF-8 of its
//! receipt with the two trailing fields (`signer_pubkey`, `signature`)
//! absent. Reconstruction is a pure TEXT operation — the trailing signature
//! block is stripped without re-serializing any JSON, so byte fidelity is
//! preserved.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// RFC 6962 leaf hash: `SHA-256(0x00 || leaf_bytes)`.
///
/// `leaf_bytes` are the exact bytes of a CuNi signed receipt JSON file.
pub fn leaf_hash(leaf_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(leaf_bytes);
    h.finalize().into()
}

/// RFC 6962 interior node hash: `SHA-256(0x01 || left || right)`.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// RFC 6962 Merkle tree root over the leaves.
///
/// An odd node at any level is promoted unchanged. An empty leaf list yields
/// the all-zero root (RFC 6962 leaves the empty tree undefined; the zero
/// root is this crate's documented convention). A single leaf's root is its
/// leaf hash.
pub fn compute_root(leaves: &[Vec<u8>]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| leaf_hash(l)).collect();
    if level.is_empty() {
        return [0u8; 32];
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut it = level.into_iter();
        loop {
            match (it.next(), it.next()) {
                (Some(a), Some(b)) => next.push(node_hash(&a, &b)),
                (Some(a), None) => next.push(a), // odd node promoted unchanged
                _ => break, // (None, None); (None, Some(_)) is impossible
            }
        }
        level = next;
    }
    level[0]
}

/// RFC 6962 inclusion proof for one leaf of a tree.
///
/// Sibling convention: `siblings[k]` is the hash at tree level `k` (level 0
/// is the leaf level) that must be combined with the running hash to move up
/// one level. When the proven node has no sibling at a level — it was the odd
/// node out and got promoted unchanged — its own hash is recorded as the
/// sibling; [`verify_inclusion`] treats `sibling == current` as a promotion.
/// (A genuine sibling hash colliding with the current hash would require a
/// SHA-256 collision and is treated as impossible.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Index of the proven leaf within the original leaf list.
    pub leaf_index: u64,
    /// Per-level sibling (or promotion stand-in) hashes, leaf level first.
    pub siblings: Vec<[u8; 32]>,
    /// Number of leaves in the tree the proof was built over.
    pub leaf_count: u64,
}

/// Build the inclusion proof for the leaf at `index`.
///
/// Returns `Err` when the tree is empty or `index` is out of range.
pub fn prove(leaves: &[Vec<u8>], index: u64) -> Result<InclusionProof, String> {
    let n = leaves.len();
    if n == 0 {
        return Err("cannot prove inclusion in an empty tree".to_string());
    }
    let mut pos: usize = index
        .try_into()
        .map_err(|_| "leaf index does not fit in usize".to_string())?;
    if pos >= n {
        return Err(format!("leaf index {index} out of range for {n} leaves"));
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| leaf_hash(l)).collect();
    let mut siblings = Vec::new();
    while level.len() > 1 {
        if pos % 2 == 1 {
            siblings.push(level[pos - 1]); // sibling on the left
        } else if pos + 1 < level.len() {
            siblings.push(level[pos + 1]); // sibling on the right
        } else {
            siblings.push(level[pos]); // promoted: stand-in is the node itself
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut it = level.into_iter();
        loop {
            match (it.next(), it.next()) {
                (Some(a), Some(b)) => next.push(node_hash(&a, &b)),
                (Some(a), None) => next.push(a),
                _ => break, // (None, None); (None, Some(_)) is impossible
            }
        }
        pos /= 2;
        level = next;
    }
    Ok(InclusionProof {
        leaf_index: index,
        siblings,
        leaf_count: n as u64,
    })
}

/// Verify an inclusion proof against an expected root.
///
/// Recomputes the root from `leaf_bytes` by walking up the proof: a sibling
/// equal to the running hash is a promotion (hash unchanged); otherwise the
/// running hash goes on the left or right according to the index parity at
/// that level.
///
/// Returns `false` — never panics — on any mismatch: wrong leaf bytes,
/// swapped or altered siblings, a proof whose length or metadata does not
/// fit `leaf_count`, an out-of-range index, or a root that does not match
/// the recomputed one.
pub fn verify_inclusion(
    leaf_bytes: &[u8],
    proof: &InclusionProof,
    expected_root: &[u8; 32],
) -> bool {
    let n = proof.leaf_count;
    if n == 0 || proof.leaf_index >= n {
        return false;
    }
    // A tree of n leaves has ceil(log2(n)) levels above the leaves; the proof
    // must carry exactly one sibling per level.
    let mut expected_len: u64 = 0;
    let mut m = n;
    while m > 1 {
        m = m.div_ceil(2);
        expected_len += 1;
    }
    if proof.siblings.len() as u64 != expected_len {
        return false;
    }
    let mut current = leaf_hash(leaf_bytes);
    let mut pos = proof.leaf_index;
    for sib in &proof.siblings {
        if sib == &current {
            // Promoted node: hash unchanged.
        } else if pos % 2 == 0 {
            current = node_hash(&current, sib);
        } else {
            current = node_hash(sib, &current);
        }
        pos /= 2;
    }
    &current == expected_root
}

/// Reconstruct the exact unsigned receipt bytes from a signed receipt text.
///
/// CuNi signs the exact UTF-8 of its receipt with the two trailing fields
/// (`signer_pubkey`, `signature`) absent. Per CuNi's format those two fields
/// are always last, so reconstruction is a pure TEXT operation: the trailing
/// block
///
/// ```text
/// ,\n  "signer_pubkey": "<hex>",\n  "signature": "<hex>"
/// ```
///
/// is removed from the receipt text. The JSON is never re-serialized, so the
/// returned bytes are byte-identical to what CuNi signed.
///
/// Trailing whitespace after the final `}` is canonicalized away: CuNi signs
/// `<body>\n}\n` exactly, so the returned bytes always end with a single
/// `\n`. Bytes from shell redirection (e.g. an extra newline after `--json`
/// output) are not part of the signed bytes and are stripped.
///
/// Returns `Err` when the trailing signature block is missing, malformed, or
/// not the last thing in the text (aside from the closing brace and
/// whitespace).
pub fn unsigned_bytes(signed_receipt_text: &str) -> Result<Vec<u8>, String> {
    let text = signed_receipt_text;
    let sig_field = ",\n  \"signature\": \"";
    let sig_pos = text
        .rfind(sig_field)
        .ok_or_else(|| "missing trailing \"signature\" field".to_string())?;
    let after_sig = &text[sig_pos + sig_field.len()..];
    let close = after_sig
        .find('"')
        .ok_or_else(|| "malformed \"signature\" value".to_string())?;
    let sig_hex = &after_sig[..close];
    check_sig_hex(sig_hex)?;
    let tail = &after_sig[close + 1..];
    if tail.trim() != "}" {
        return Err("trailing \"signature\" field is not the last field".to_string());
    }
    let before = &text[..sig_pos];
    let pk_field = ",\n  \"signer_pubkey\": \"";
    let pk_pos = before
        .rfind(pk_field)
        .ok_or_else(|| "missing trailing \"signer_pubkey\" field".to_string())?;
    // `before` ends exactly at the start of the signature field, so the
    // signer_pubkey value is the remainder: `<hex>"`.
    let pk_val = &before[pk_pos + pk_field.len()..];
    let pubkey_hex = pk_val
        .strip_suffix('"')
        .ok_or_else(|| "malformed \"signer_pubkey\" value".to_string())?;
    check_pubkey_hex(pubkey_hex)?;
    // Remove the block [pk_pos, block_end) from the original text.
    let block_end = sig_pos + sig_field.len() + close + 1;
    let mut out = Vec::with_capacity(text.len() - (block_end - pk_pos));
    out.extend_from_slice(&text.as_bytes()[..pk_pos]);
    out.extend_from_slice(&text.as_bytes()[block_end..]);
    // Canonicalize trailing whitespace: cuni signs `<body>\n}\n` exactly;
    // bytes after the final `}` (e.g. an extra newline from shell
    // redirection of `--json` output) are NOT part of the signed bytes.
    let mut s = String::from_utf8(out)
        .map_err(|_| "receipt is not valid UTF-8".to_string())?;
    let trimmed = s.trim_end().to_string();
    if !trimmed.ends_with('}') {
        return Err("unsigned receipt does not end with '}'".to_string());
    }
    s = format!("{trimmed}\n");
    Ok(s.into_bytes())
}

fn check_pubkey_hex(s: &str) -> Result<(), String> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("signer_pubkey must be 64 hex chars (32-byte Ed25519 key)".to_string());
    }
    Ok(())
}

fn check_sig_hex(s: &str) -> Result<(), String> {
    if s.len() != 128 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("signature must be 128 hex chars (64-byte Ed25519 signature)".to_string());
    }
    Ok(())
}

/// Verify an Ed25519 signature over unsigned receipt bytes.
///
/// Returns `false` — never panics — when either hex string is malformed, the
/// decoded key or signature has the wrong length, the key is not a valid
/// curve point, or the signature does not verify.
pub fn verify_receipt_signature(unsigned: &[u8], pubkey_hex: &str, sig_hex: &str) -> bool {
    let pk_bytes = match hex::decode(pubkey_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk_arr: [u8; 32] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(v) => v,
        Err(_) => return false,
    };
    vk.verify(unsigned, &Signature::from_bytes(&sig_arr))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(bytes: &[u8; 32]) -> String {
        hex::encode(bytes)
    }

    // ------------------------------------------------------------------
    // RFC 6962 known-answer vectors.
    //
    // Generated independently with:
    //   python3 -c "import hashlib; print(hashlib.sha256(b'\x00'+b'hello').hexdigest())"
    //   -> 8a2a5c9b768827de5a9552c38a044c66959c68f6d2f21b5260af54d2f87db827
    //   python3 -c "import hashlib; print(hashlib.sha256(b'\x00').hexdigest())"
    //   -> 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
    //   python3 -c "
    //   import hashlib
    //   l1 = hashlib.sha256(b'\x00'+b'hello').digest()
    //   l2 = hashlib.sha256(b'\x00'+b'world').digest()
    //   print(hashlib.sha256(b'\x01'+l1+l2).hexdigest())"
    //   -> 24233339aadcedf287d262413f03c028eb8db397edd32a2878091151b99bf20f
    // ------------------------------------------------------------------
    #[test]
    fn rfc6962_leaf_known_answers() {
        assert_eq!(
            hex_of(&leaf_hash(b"hello")),
            "8a2a5c9b768827de5a9552c38a044c66959c68f6d2f21b5260af54d2f87db827"
        );
        assert_eq!(
            hex_of(&leaf_hash(b"")),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }

    #[test]
    fn rfc6962_node_known_answer() {
        // compute_root over two leaves is exactly node_hash(l1, l2).
        let root = compute_root(&[b"hello".to_vec(), b"world".to_vec()]);
        assert_eq!(
            hex_of(&root),
            "24233339aadcedf287d262413f03c028eb8db397edd32a2878091151b99bf20f"
        );
    }

    // ------------------------------------------------------------------
    // Prove/verify across even and odd leaf counts.
    // ------------------------------------------------------------------
    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
    }

    #[test]
    fn prove_verify_all_indices() {
        for n in [1usize, 2, 3, 5, 8] {
            let ls = leaves(n);
            let root = compute_root(&ls);
            for i in 0..n {
                let proof = prove(&ls, i as u64).expect("in-range index");
                assert_eq!(proof.leaf_index, i as u64);
                assert_eq!(proof.leaf_count, n as u64);
                assert!(
                    verify_inclusion(&ls[i], &proof, &root),
                    "n={n} index={i} must verify"
                );
            }
        }
    }

    #[test]
    fn prove_out_of_range_is_err() {
        let ls = leaves(3);
        assert!(prove(&ls, 3).is_err());
        assert!(prove(&ls, 100).is_err());
        assert!(prove(&[], 0).is_err());
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let ls = leaves(1);
        assert_eq!(compute_root(&ls), leaf_hash(&ls[0]));
    }

    // ------------------------------------------------------------------
    // Tamper tests.
    // ------------------------------------------------------------------
    #[test]
    fn tamper_flipped_bit_fails() {
        let ls = leaves(5);
        let root = compute_root(&ls);
        let proof = prove(&ls, 2).unwrap();
        let mut bad = ls[2].clone();
        bad[0] ^= 0x01; // flip one bit
        assert!(!verify_inclusion(&bad, &proof, &root));
    }

    #[test]
    fn tamper_swapped_siblings_fails() {
        let ls = leaves(5);
        let root = compute_root(&ls);
        let mut proof = prove(&ls, 4).unwrap();
        // Leaf 4 of a 5-leaf tree is promoted twice, so siblings[0] and
        // siblings[1] are the same stand-in hash; swap across distinct levels.
        assert!(proof.siblings.len() == 3);
        assert_ne!(proof.siblings[0], proof.siblings[2]);
        proof.siblings.swap(0, 2);
        assert!(!verify_inclusion(&ls[4], &proof, &root));
    }

    #[test]
    fn tamper_wrong_root_fails() {
        let ls = leaves(5);
        let root = compute_root(&ls);
        let proof = prove(&ls, 1).unwrap();
        let mut bad_root = root;
        bad_root[0] ^= 0xff;
        assert!(!verify_inclusion(&ls[1], &proof, &bad_root));
    }

    #[test]
    fn tamper_wrong_leaf_fails() {
        let ls = leaves(3);
        let root = compute_root(&ls);
        let proof = prove(&ls, 0).unwrap();
        assert!(!verify_inclusion(b"some other leaf", &proof, &root));
    }

    // ------------------------------------------------------------------
    // Receipt signature round-trip.
    // ------------------------------------------------------------------
    /// Sample receipt in the CuNi `cuni check --sign` (v0.10.0) format:
    /// 2-space indented JSON, with the two trailing signature fields last.
    /// serde_json with preserve_order is used to assert the required fields
    /// are present and stay in order (signing must never re-serialize).
    fn sample_unsigned_receipt() -> String {
        let text = "{\n  \"path\": \"example.py\",\n  \"source_hash\": \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\n  \"cuni_version\": \"0.10.0\",\n  \"exact\": true,\n  \"summary\": \"EXACT\",\n  \"langs\": [\"python\"],\n  \"seats_ran\": 5,\n  \"stdout_hash\": \"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\",\n  \"seats\": [\"py\", \"js\", \"ts\", \"c\", \"cpp\"]\n}";
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        let obj = v.as_object().unwrap();
        let required = [
            "path",
            "source_hash",
            "cuni_version",
            "exact",
            "summary",
            "langs",
            "seats_ran",
            "stdout_hash",
            "seats",
        ];
        for f in required {
            assert!(obj.contains_key(f), "missing required field {f}");
        }
        // Fields keep file order (no re-serialization happens anywhere).
        let keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
        assert_eq!(keys, required);
        text.to_string()
    }

    fn signed_fixture() -> (Vec<u8>, String, String, String) {
        use ed25519_dalek::{Signer, SigningKey};
        let unsigned_text = sample_unsigned_receipt();
        // Canonical signed form: CuNi signs `<body>\n}\n` exactly.
        let canonical = format!("{}\n", unsigned_text);
        let unsigned = canonical.as_bytes().to_vec();
        // Deterministic test keypair (no randomness needed).
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let sig = sk.sign(&unsigned);
        let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());
        let sig_hex = hex::encode(sig.to_bytes());
        // CuNi inserts the two trailing fields before the final newline+brace:
        // signed = unsigned-minus-"\n}" + block + "\n}", so stripping the
        // block yields the unsigned text byte-exactly.
        let body = unsigned_text
            .strip_suffix("\n}")
            .expect("fixture ends with newline+brace");
        let signed = format!(
            "{body},\n  \"signer_pubkey\": \"{pubkey_hex}\",\n  \"signature\": \"{sig_hex}\"\n}}"
        );
        (unsigned, signed, pubkey_hex, sig_hex)
    }

    #[test]
    fn signature_round_trip_verifies() {
        let (unsigned, signed, pubkey_hex, sig_hex) = signed_fixture();
        let stripped = unsigned_bytes(&signed).expect("valid signed receipt");
        assert_eq!(stripped, unsigned, "strip must be byte-exact");
        assert!(verify_receipt_signature(&stripped, &pubkey_hex, &sig_hex));
    }

    #[test]
    fn signature_wrong_pubkey_fails() {
        use ed25519_dalek::SigningKey;
        let (unsigned, _signed, _pubkey_hex, sig_hex) = signed_fixture();
        let other = SigningKey::from_bytes(&[0x99u8; 32]);
        let other_hex = hex::encode(other.verifying_key().to_bytes());
        assert!(!verify_receipt_signature(&unsigned, &other_hex, &sig_hex));
    }

    #[test]
    fn signature_corrupted_sig_fails() {
        let (unsigned, _signed, pubkey_hex, sig_hex) = signed_fixture();
        let mut sig_bytes = hex::decode(&sig_hex).unwrap();
        sig_bytes[0] ^= 0x01;
        let bad_sig_hex = hex::encode(&sig_bytes);
        assert!(!verify_receipt_signature(&unsigned, &pubkey_hex, &bad_sig_hex));
    }

    #[test]
    fn signature_malformed_inputs_fail() {
        let (unsigned, _signed, pubkey_hex, sig_hex) = signed_fixture();
        assert!(!verify_receipt_signature(&unsigned, "zz", &sig_hex));
        assert!(!verify_receipt_signature(&unsigned, &pubkey_hex, "00"));
        assert!(!verify_receipt_signature(&unsigned, &pubkey_hex, &sig_hex[..126]));
    }

    #[test]
    fn unsigned_bytes_strips_exactly() {
        let (unsigned, signed, _pk, _sig) = signed_fixture();
        // The signed text ends with "<sig>"\n}; stripping removes exactly the
        // trailing block, leaving the unsigned text plus its closing brace.
        let stripped = unsigned_bytes(&signed).unwrap();
        assert_eq!(stripped, unsigned);
        // Sanity: the signed text really does end with the sig block + brace.
        assert!(signed.trim_end().ends_with('}'));
        assert!(signed.contains("\"signature\": \""));
    }

    #[test]
    fn unsigned_bytes_missing_fields_is_err() {
        let bare = sample_unsigned_receipt();
        assert!(unsigned_bytes(&bare).is_err());
        assert!(unsigned_bytes("{\"a\": 1}").is_err());
        assert!(unsigned_bytes("").is_err());
    }

    #[test]
    fn unsigned_bytes_signature_not_last_is_err() {
        let (_unsigned, signed, _pk, _sig) = signed_fixture();
        // Append junk after the signature block: no longer the last field.
        let doctored = format!("{signed}\n{{\"extra\": true}}");
        assert!(unsigned_bytes(&doctored).is_err());
    }
}
