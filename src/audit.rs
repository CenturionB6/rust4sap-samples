//! Append-only audit log with a versioned hash chain.
//!
//! # What each entry commits to
//!
//! The hash covers, in order: `seq`, `at_unix`, `subject`, `action`, `entity`, `allowed`,
//! `subject_verified`, `client`, `token_fp`, `untrusted_iss`, `untrusted_sub`, `auth_stage`,
//! `prev_hash` (format v2). Every field is therefore tamper-evident, including the
//! attribution metadata.
//!
//! `subject_verified = false` means the `subject` field is the literal `unauthenticated`:
//! an authentication failure. In that case `untrusted_iss` / `untrusted_sub` are **claims read
//! from an unverified token** — diagnostic evidence for correlation, never identity. They are
//! deliberately separate fields so no consumer can mistake them for a verified subject.
//!
//! # What the chain does and does not prove
//!
//! It proves that an entry was not altered in isolation *relative to another copy of the same
//! chain*: recomputing one hash breaks every later `prev_hash`. It does **not** protect against
//! an administrator who controls the store and rewrites the entire file, because the chain is
//! unkeyed and self-contained. Detectability therefore requires retaining checkpoints somewhere
//! else and comparing them.
//!
//! # Format versions
//!
//! - **v0** — 7 hashed fields (decision only).
//! - **v1** — 12 fields (attribution added: verified status, client, token fingerprint,
//!   untrusted claims). Entries written by that code carry no version marker.
//! - **v2** — 13 fields (`auth_stage` added). Every v2 entry declares `"v": 2`.
//!
//! Old entries are never rewritten. Verification detects the format per entry: an entry with a
//! `v` field is checked with that version only; an entry without one is checked against v0 and
//! v1, and must match exactly one. Unknown versions and ambiguous matches are errors, not
//! guesses.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Cursor, Write};
use std::path::{Path, PathBuf};

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Hash-chain format this entry was written with. Absent on legacy v0/v1 entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v: Option<u32>,
    pub seq: u64,
    pub at_unix: u64,
    pub subject: String,
    pub action: String,
    pub entity: String,
    pub allowed: bool,
    pub reason: String,
    /// true only when `subject` came from a verified token. Auth failures are false and carry
    /// the diagnostic fields below instead — never merged into `subject`.
    #[serde(default)]
    pub subject_verified: bool,
    /// verified client identity, when the client token itself verified
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// SHA-256 fingerprint of the presented token; never the token
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_fp: Option<String>,
    /// claims from an *unverified* token — diagnostic hints only, deliberately separate
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub untrusted_iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub untrusted_sub: Option<String>,
    /// which stage refused the request: client_credential, employee_credential,
    /// delegation_binding, identity_resolution, credentials_missing
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_stage: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

pub struct AuditLog {
    path: PathBuf,
    seq: u64,
    last_hash: String,
    /// auth-failure flood guard: at most this many attributed failures per window
    auth_window_start: u64,
    auth_in_window: u32,
}

/// Current hash-chain format. Bump only with a verifier that still reads every older version.
pub const AUDIT_VERSION: u32 = 2;

pub const AUTH_FAILURES_PER_WINDOW: u32 = 60;
pub const AUTH_WINDOW_SECS: u64 = 60;

impl AuditLog {
    /// Open (or create) the log, continuing the chain from the last entry.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        // An existing file is evidence, not a cache: verify the whole chain, never just the
        // last line. A torn tail must refuse rather than silently restart the sequence.
        // stream the history: bounded memory, full-chain verification
        let (seq, last_hash) = match std::fs::File::open(&path) {
            Ok(f) => {
                let report = verify_reader(BufReader::new(f)).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("audit_integrity: refusing to append to an unverifiable history: {e}"),
                    )
                })?;
                (report.last_seq, report.last_hash)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, String::new()),
            Err(e) => return Err(e),
        };
        Ok(Self {
            path,
            seq,
            last_hash,
            auth_window_start: 0,
            auth_in_window: 0,
        })
    }

    /// Record an authentication failure with attribution.
    ///
    /// Flood guard: once the window budget is spent, one suppression entry is written and
    /// further failures in that window are counted, not appended. Silently dropping evidence
    /// would be worse than saying "N more were suppressed".
    pub fn append_auth_failure(
        &mut self,
        tool: &str,
        code: &str,
        stage: &str,
        token_fp: Option<String>,
        client: Option<String>,
        untrusted_iss: Option<String>,
        untrusted_sub: Option<String>,
    ) -> std::io::Result<Option<Entry>> {
        let now = unix_now();
        if now.saturating_sub(self.auth_window_start) >= AUTH_WINDOW_SECS {
            self.auth_window_start = now;
            self.auth_in_window = 0;
        }
        self.auth_in_window += 1;
        if self.auth_in_window > AUTH_FAILURES_PER_WINDOW {
            if self.auth_in_window == AUTH_FAILURES_PER_WINDOW + 1 {
                return self
                    .append_full(
                        "unauthenticated",
                        "Auth",
                        tool,
                        false,
                        &format!("{code}; further failures suppressed this window"),
                        false,
                        client,
                        token_fp,
                        untrusted_iss,
                        untrusted_sub,
                        Some(stage.to_string()),
                    )
                    .map(Some);
            }
            return Ok(None);
        }

        self.append_full(
            "unauthenticated",
            "Auth",
            tool,
            false,
            code,
            false,
            client,
            token_fp,
            untrusted_iss,
            untrusted_sub,
            Some(stage.to_string()),
        )
        .map(Some)
    }

    pub fn append(&mut self, subject: &str, action: &str, entity: &str, allowed: bool, reason: &str) -> std::io::Result<Entry> {
        self.append_full(subject, action, entity, allowed, reason, true, None, None, None, None, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn append_full(
        &mut self,
        subject: &str,
        action: &str,
        entity: &str,
        allowed: bool,
        reason: &str,
        subject_verified: bool,
        client: Option<String>,
        token_fp: Option<String>,
        untrusted_iss: Option<String>,
        untrusted_sub: Option<String>,
        auth_stage: Option<String>,
    ) -> std::io::Result<Entry> {
        self.seq += 1;
        let at_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let prev_hash = self.last_hash.clone();
        let hash = hash_of(
            AUDIT_VERSION,
            self.seq,
            at_unix,
            subject,
            action,
            entity,
            allowed,
            subject_verified,
            client.as_deref(),
            token_fp.as_deref(),
            untrusted_iss.as_deref(),
            untrusted_sub.as_deref(),
            auth_stage.as_deref(),
            &prev_hash,
        );

        let entry = Entry {
            v: Some(AUDIT_VERSION),
            seq: self.seq,
            at_unix,
            subject: subject.into(),
            action: action.into(),
            entity: entity.into(),
            allowed,
            reason: reason.into(),
            subject_verified,
            client,
            token_fp,
            untrusted_iss,
            untrusted_sub,
            auth_stage,
            prev_hash: prev_hash.clone(),
            hash: hash.clone(),
        };

        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(&entry).unwrap_or_default())?;
        self.last_hash = hash;
        Ok(entry)
    }

    pub fn tail(&self, n: usize) -> Vec<Entry> {
        let body = std::fs::read_to_string(&self.path).unwrap_or_default();
        body.lines()
            .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
            .rev()
            .take(n)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }
}

/// Recompute the chain and report the first entry that does not verify.
/// Hash one entry under a specific format version. Shared by writer and verifier so the two
/// can never drift.
#[allow(clippy::too_many_arguments)]
fn hash_of(
    version: u32,
    seq: u64,
    at: u64,
    subject: &str,
    action: &str,
    entity: &str,
    allowed: bool,
    subject_verified: bool,
    client: Option<&str>,
    token_fp: Option<&str>,
    untrusted_iss: Option<&str>,
    untrusted_sub: Option<&str>,
    auth_stage: Option<&str>,
    prev_hash: &str,
) -> String {
    let mut h = Sha256::new();
    match version {
        0 => h.update(format!("{seq}|{at}|{subject}|{action}|{entity}|{allowed}|{prev_hash}")),
        1 => h.update(format!(
            "{seq}|{at}|{subject}|{action}|{entity}|{allowed}|{subject_verified}|{}|{}|{}|{}|{prev_hash}",
            client.unwrap_or_default(),
            token_fp.unwrap_or_default(),
            untrusted_iss.unwrap_or_default(),
            untrusted_sub.unwrap_or_default(),
        )),
        2 => h.update(format!(
            "{seq}|{at}|{subject}|{action}|{entity}|{allowed}|{subject_verified}|{}|{}|{}|{}|{}|{prev_hash}",
            client.unwrap_or_default(),
            token_fp.unwrap_or_default(),
            untrusted_iss.unwrap_or_default(),
            untrusted_sub.unwrap_or_default(),
            auth_stage.unwrap_or_default(),
        )),
        _ => h.update("unsupported-version"),
    }
    hex::encode(h.finalize())
}

/// Result of verifying a file: how many entries, and which formats they used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub entries: usize,
    /// format versions encountered, in order of first appearance
    pub versions: Vec<u32>,
    /// last verified sequence number and hash, for continuing a chain
    pub last_seq: u64,
    pub last_hash: String,
}

pub fn verify(path: impl AsRef<Path>) -> Result<VerifyReport, String> {
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    verify_reader(BufReader::new(f))
}

/// Verify a file body already in memory. Kept for callers that have the bytes.
pub fn verify_body(body: &str) -> Result<VerifyReport, String> {
    verify_reader(Cursor::new(body))
}

/// Streaming verification: memory use is one line, not the whole history.
///
/// Each entry is checked with its declared format, or — for legacy entries with no marker —
/// with the exactly-one-format rule. Unknown or ambiguous formats are errors, never guesses.
pub fn verify_reader<R: BufRead>(mut reader: R) -> Result<VerifyReport, String> {
    let mut prev = String::new();
    let mut count = 0usize;
    let mut versions: Vec<u32> = Vec::new();
    let mut last_seq = 0u64;
    let mut last_hash = String::new();
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).map_err(|e| format!("read error: {e}"))?;
        if n == 0 {
            break;
        }
        let text = line.trim_end_matches(['\n', '\r']);
        if text.trim().is_empty() {
            continue;
        }
        let e: Entry = serde_json::from_str(text).map_err(|e| format!("unparseable entry: {e}"))?;

        let version = match e.v {
            Some(v @ 0..=AUDIT_VERSION) => v,
            Some(v) => {
                return Err(format!(
                    "entry {} declares unsupported audit format v{v} (this build reads 0..={AUDIT_VERSION})",
                    e.seq
                ))
            }
            None => {
                let matches: Vec<u32> = [0u32, 1]
                    .into_iter()
                    .filter(|v| {
                        hash_of(*v, e.seq, e.at_unix, &e.subject, &e.action, &e.entity, e.allowed,
                                e.subject_verified, e.client.as_deref(), e.token_fp.as_deref(),
                                e.untrusted_iss.as_deref(), e.untrusted_sub.as_deref(),
                                e.auth_stage.as_deref(), &e.prev_hash) == e.hash
                    })
                    .collect();
                match matches.as_slice() {
                    [one] => *one,
                    [] => return Err(format!("entry {} hash mismatch (no known format matches)", e.seq)),
                    _ => {
                        return Err(format!(
                            "entry {} is ambiguous: it matches multiple legacy formats; refusing to guess",
                            e.seq
                        ))
                    }
                }
            }
        };

        let expect = hash_of(version, e.seq, e.at_unix, &e.subject, &e.action, &e.entity, e.allowed,
                             e.subject_verified, e.client.as_deref(), e.token_fp.as_deref(),
                             e.untrusted_iss.as_deref(), e.untrusted_sub.as_deref(),
                             e.auth_stage.as_deref(), &e.prev_hash);
        if e.hash != expect {
            return Err(format!("entry {} hash mismatch under format v{version}", e.seq));
        }
        if e.prev_hash != prev {
            return Err(format!("entry {} does not chain to its predecessor", e.seq));
        }
        if !versions.contains(&version) {
            versions.push(version);
        }
        prev = e.hash.clone();
        last_seq = e.seq;
        last_hash = e.hash.clone();
        count += 1;
    }

    Ok(VerifyReport { entries: count, versions, last_seq, last_hash })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let mut log = AuditLog::open(&path).unwrap();
            log.append("alice", "read", "A_BusinessPartner", true, "allowed by r1").unwrap();
            log.append("alice", "read", "A_Sensitive", false, "no rule allows").unwrap();
            log.append("bob", "list", "A_BusinessPartner", true, "allowed by r2").unwrap();
        }
        assert_eq!(verify(&path).unwrap().entries, 3);

        // tamper with the middle entry's decision, keep everything else
        let body = std::fs::read_to_string(&path).unwrap();
        let tampered = body.replace("\"allowed\":false", "\"allowed\":true");
        std::fs::write(&path, tampered).unwrap();
        assert!(verify(&path).is_err(), "tampering must break the chain");
    }

    #[test]
    fn reopening_continues_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        AuditLog::open(&path).unwrap().append("a", "read", "E", true, "ok").unwrap();
        let mut second = AuditLog::open(&path).unwrap();
        let e = second.append("b", "read", "E", true, "ok").unwrap();
        assert_eq!(e.seq, 2);
        assert_eq!(verify(&path).unwrap().entries, 2);
    }
}
