//! `publisher` — hourly append job for the CuNi transparency log.
//!
//! Reads `submissions/pending/*.json`; for each receipt: checks the required
//! fields, reconstructs the unsigned bytes and verifies the Ed25519 signature
//! against the receipt's OWN stated `signer_pubkey` (self-consistency — the
//! log proves existence + self-consistency, NOT authority), dedupes by leaf
//! hash, and appends valid receipts. Then recomputes the RFC 6962 root over
//! ALL leaves (via `ctlog`), writes `log/roots/<utc-hour>.json` +
//! `log/roots/latest.json`, and regenerates every inclusion proof.
//!
//! Idempotent: when nothing was appended and the root is unchanged, no root
//! or proof files are rewritten (missing proofs are still regenerated).

use ctlog::{compute_root, leaf_hash, prove, unsigned_bytes, verify_receipt_signature};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_FIELDS: &[&str] = &[
    "path",
    "source_hash",
    "cuni_version",
    "exact",
    "stdout_hash",
    "seats",
    "signer_pubkey",
    "signature",
];

/// Max pending files processed per run.
const MAX_PER_RUN: usize = 500;

fn repo_root() -> PathBuf {
    // The binary runs from the repo root (see the hourly workflow).
    std::env::current_dir().expect("cannot determine current dir")
}

fn read_leaves(root: &Path) -> Vec<(u64, Vec<u8>)> {
    let dir = root.join("log/leaves");
    let mut out = Vec::new();
    let entries = fs::read_dir(&dir).unwrap_or_else(|_| {
        fs::create_dir_all(&dir).expect("create log/leaves");
        fs::read_dir(&dir).expect("read log/leaves")
    });
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".json") || name.len() != 13 {
            continue;
        }
        let seq: u64 = match name[..8].parse() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if let Ok(bytes) = fs::read(e.path()) {
            out.push((seq, bytes));
        }
    }
    out.sort_by_key(|(s, _)| *s);
    out
}

/// Current UTC hour truncated, e.g. "2026-10-09T19:00:00Z".
/// Uses the proleptic Gregorian calendar (Howard Hinnant's civil_from_days).
fn current_utc_hour() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_secs();
    let days = (secs / 86_400) as i64;
    let hour = (secs % 86_400) / 3600;
    // days -> civil date
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:00:00Z")
}

/// Validate one pending receipt. Returns Ok(leaf_hash) or Err(reason).
fn validate_receipt(bytes: &[u8]) -> Result<[u8; 32], String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "BAD_UTF8: receipt is not valid UTF-8".to_string())?;
    let doc: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("BAD_JSON: {e}"))?;
    let obj = doc.as_object().ok_or_else(|| "BAD_JSON: receipt is not a JSON object".to_string())?;
    for f in REQUIRED_FIELDS {
        if !obj.contains_key(*f) {
            return Err(format!("MISSING_FIELDS: required field `{f}` absent"));
        }
    }
    let pubkey_hex = obj["signer_pubkey"]
        .as_str()
        .ok_or_else(|| "BAD_FIELDS: signer_pubkey is not a string".to_string())?;
    let sig_hex = obj["signature"]
        .as_str()
        .ok_or_else(|| "BAD_FIELDS: signature is not a string".to_string())?;
    // Normalize trailing newlines for the verification input only: cuni
    // --json appends one via println!, --receipt writes none extra, but cuni
    // always signs <body>\n}\n. Leaf bytes kept exact; only this input is
    // normalized.
    let normalized = format!("{}\n", text.trim_end_matches('\n'));
    let unsigned = unsigned_bytes(&normalized)
        .map_err(|e| format!("BAD_SIGNATURE_BLOCK: {e}"))?;
    if !verify_receipt_signature(&unsigned, pubkey_hex, sig_hex) {
        return Err("BAD_SIGNATURE: Ed25519 verification failed against the receipt's own signer_pubkey".to_string());
    }
    Ok(leaf_hash(bytes))
}

fn write_json(path: &Path, value: &serde_json::Value) {
    let mut s = serde_json::to_string_pretty(value).expect("serialize json");
    s.push('\n');
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent dirs");
    }
    fs::write(path, s).expect("write json file");
}

fn main() {
    let root = repo_root();
    for d in [
        "log/leaves",
        "log/roots",
        "log/proofs",
        "submissions/pending",
        "submissions/accepted",
        "submissions/rejected",
    ] {
        fs::create_dir_all(root.join(d)).expect("create dir");
    }

    let mut leaves = read_leaves(&root); // sorted by seq
    let mut known: HashSet<[u8; 32]> = leaves.iter().map(|(_, b)| leaf_hash(b)).collect();
    let mut next_seq: u64 = leaves.iter().map(|(s, _)| s + 1).max().unwrap_or(0);

    // Pending files, sorted for determinism, capped per run.
    let mut pending: Vec<PathBuf> = fs::read_dir(root.join("submissions/pending"))
        .expect("read pending")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    pending.sort();
    pending.truncate(MAX_PER_RUN);

    let mut appended = 0usize;
    let mut duplicates = 0usize;
    let mut rejected = 0usize;
    let mut reject_reasons: HashMap<String, usize> = HashMap::new();

    for path in pending {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                rejected += 1;
                let reason = format!("UNREADABLE: {e}");
                *reject_reasons.entry(reason.clone()).or_insert(0) += 1;
                fs::write(root.join("submissions/rejected").join(format!("{name}.reason")), &reason)
                    .expect("write reason");
                let _ = fs::remove_file(&path);
                continue;
            }
        };
        match validate_receipt(&bytes) {
            Ok(lh) => {
                if known.contains(&lh) {
                    duplicates += 1;
                } else {
                    let leaf_name = format!("{next_seq:08}.json");
                    fs::write(root.join("log/leaves").join(&leaf_name), &bytes)
                        .expect("write leaf");
                    leaves.push((next_seq, bytes));
                    known.insert(lh);
                    next_seq += 1;
                    appended += 1;
                }
                // Valid (or duplicate-valid): keep the original filename.
                let _ = fs::rename(&path, root.join("submissions/accepted").join(&name));
            }
            Err(reason) => {
                rejected += 1;
                *reject_reasons.entry(reason.clone()).or_insert(0) += 1;
                let rdir = root.join("submissions/rejected");
                let _ = fs::rename(&path, rdir.join(&name));
                fs::write(rdir.join(format!("{name}.reason")), &reason).expect("write reason");
            }
        }
    }

    // Recompute the root over ALL leaves (leaf bytes in seq order).
    let leaf_bytes: Vec<Vec<u8>> = leaves.iter().map(|(_, b)| b.clone()).collect();
    let new_root = compute_root(&leaf_bytes);
    let new_root_hex = hex::encode(new_root);
    let hour = current_utc_hour();
    let leaf_count = leaves.len();

    // Idempotency: skip root writes when the root is unchanged.
    let latest_path = root.join("log/roots/latest.json");
    let unchanged = fs::read_to_string(&latest_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("root").and_then(|r| r.as_str()).map(|s| s.to_string()))
        .zip(
            fs::read_to_string(&latest_path)
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .and_then(|v| v.get("leaf_count").and_then(|c| c.as_u64())),
        )
        .map(|(r, c)| r == new_root_hex && c as usize == leaf_count)
        .unwrap_or(false);

    let proofs_complete = (0..leaf_count as u64).all(|i| {
        root.join("log/proofs").join(format!("{i:08}.json")).exists()
    });

    if unchanged && proofs_complete {
        println!("no changes: {leaf_count} leaves, root {new_root_hex}");
        println!("CT_SUMMARY appended={appended} duplicates={duplicates} rejected={rejected} root={new_root_hex} leaf_count={leaf_count}");
        return;
    }

    // Write the hourly root file and latest.json (latest is a copy).
    let root_doc = serde_json::json!({
        "hour": hour,
        "root": new_root_hex,
        "leaf_count": leaf_count,
    });
    write_json(&root.join("log/roots").join(format!("{hour}.json")), &root_doc);
    write_json(&latest_path, &root_doc);

    // Regenerate ALL inclusion proofs against the latest root.
    for (i, _) in leaves.iter().enumerate() {
        let proof = prove(&leaf_bytes, i as u64).expect("prove in-range");
        let seq = leaves[i].0;
        let doc = serde_json::json!({
            "leaf_index": proof.leaf_index,
            "leaf_count": proof.leaf_count,
            "siblings": proof.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
            "root": new_root_hex,
            "hour": hour,
        });
        write_json(&root.join("log/proofs").join(format!("{seq:08}.json")), &doc);
    }

    println!("appended {appended} receipt(s), {duplicates} duplicate(s), {rejected} rejected");
    for (reason, n) in &reject_reasons {
        println!("  rejected x{n}: {reason}");
    }
    println!("root {new_root_hex} over {leaf_count} leaves (hour {hour})");
    println!("CT_SUMMARY appended={appended} duplicates={duplicates} rejected={rejected} root={new_root_hex} leaf_count={leaf_count}");
}
