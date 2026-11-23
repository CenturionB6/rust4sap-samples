//! Historical audit formats stay verifiable. Nothing is rewritten; a version is never guessed.

use rust4sap_policy::audit::{self, Entry};
use sha2::{Digest, Sha256};

fn h(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(parts.join("|"));
    hex::encode(hasher.finalize())
}

/// An entry as the v1 writer produced it: 12 hashed fields, no version marker.
fn legacy_v1(seq: u64, prev: &str) -> Entry {
    let (at, subject, action, entity, allowed) = (1_700_000_000u64, "clerk", "Read", "A_BusinessPartner", true);
    let verified = true;
    let hash = h(&[
        &seq.to_string(), &at.to_string(), subject, action, entity, &allowed.to_string(),
        &verified.to_string(), "", "", "", "", prev,
    ]);
    Entry {
        v: None,
        seq, at_unix: at,
        subject: subject.into(), action: action.into(), entity: entity.into(),
        allowed, reason: "allowed by buyer-de-partners".into(),
        subject_verified: verified,
        client: None, token_fp: None, untrusted_iss: None, untrusted_sub: None,
        auth_stage: None,
        prev_hash: prev.into(), hash,
    }
}

/// The oldest format: 7 hashed fields.
fn legacy_v0(seq: u64, prev: &str) -> Entry {
    let (at, subject, action, entity, allowed) = (1_600_000_000u64, "MCP_DEMO", "Read", "A_BusinessPartner", false);
    let hash = h(&[
        &seq.to_string(), &at.to_string(), subject, action, entity, &allowed.to_string(), prev,
    ]);
    Entry {
        v: None,
        seq, at_unix: at,
        subject: subject.into(), action: action.into(), entity: entity.into(),
        allowed, reason: "deny".into(),
        subject_verified: false,
        client: None, token_fp: None, untrusted_iss: None, untrusted_sub: None,
        auth_stage: None,
        prev_hash: prev.into(), hash,
    }
}

fn write(entries: &[Entry]) -> String {
    let p = format!("/tmp/audit-ver-{}-{:?}.jsonl", std::process::id(), std::thread::current().id());
    let body: String = entries.iter().map(|e| serde_json::to_string(e).unwrap() + "\n").collect();
    std::fs::write(&p, body).unwrap();
    p
}

#[test]
fn a_legacy_v1_file_still_verifies() {
    let e1 = legacy_v1(1, "");
    let e2 = legacy_v1(2, &e1.hash);
    let path = write(&[e1, e2]);
    let report = audit::verify(&path).expect("legacy file must verify");
    assert_eq!(report.entries, 2);
    assert_eq!(report.versions, vec![1]);
    let _ = std::fs::remove_file(path);
}

#[test]
fn a_legacy_v0_file_still_verifies() {
    let e1 = legacy_v0(1, "");
    let path = write(&[e1]);
    let report = audit::verify(&path).expect("oldest format must verify");
    assert_eq!(report.versions, vec![0]);
    let _ = std::fs::remove_file(path);
}

#[test]
fn new_entries_declare_version_two() {
    let path = format!("/tmp/audit-v2-{}.jsonl", std::process::id());
    let _ = std::fs::remove_file(&path);
    let mut log = audit::AuditLog::open(&path).unwrap();
    let e = log.append("clerk", "Read", "A_BusinessPartner", true, "allowed").unwrap();
    assert_eq!(e.v, Some(2));
    let report = audit::verify(&path).unwrap();
    assert_eq!(report.versions, vec![2]);
    let _ = std::fs::remove_file(path);
}

#[test]
fn a_mixed_file_verifies_each_entry_with_its_own_format_and_reports_both() {
    let old = legacy_v1(1, "");
    let path = format!("/tmp/audit-mixed-{}.jsonl", std::process::id());
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, serde_json::to_string(&old).unwrap() + "\n").unwrap();

    // continue the chain with the current writer
    let mut log = audit::AuditLog::open(&path).unwrap();
    log.append("controller", "Read", "A_BusinessPartner", true, "allowed").unwrap();

    let report = audit::verify(&path).expect("mixed file must verify entry by entry");
    assert_eq!(report.entries, 2);
    assert_eq!(report.versions, vec![1, 2], "the boundary is reported, not hidden");
    let _ = std::fs::remove_file(path);
}

#[test]
fn an_unknown_format_is_refused_rather_than_assumed() {
    let mut e = legacy_v1(1, "");
    e.v = Some(9);
    let path = write(&[e]);
    let err = audit::verify(&path).unwrap_err();
    assert!(err.contains("unsupported audit format v9"), "{err}");
    let _ = std::fs::remove_file(path);
}

#[test]
fn a_tampered_legacy_entry_is_not_quietly_accepted_as_another_version() {
    let mut e = legacy_v1(1, "");
    e.subject = "someone-else".into(); // mutate a hashed field without recomputing
    let path = write(&[e]);
    let err = audit::verify(&path).unwrap_err();
    assert!(err.contains("hash mismatch"), "{err}");
    let _ = std::fs::remove_file(path);
}
