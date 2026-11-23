//! Startup integrity: an existing audit file is evidence, so the gateway validates all of it
//! before appending. It never truncates, repairs, or restarts a broken chain.

use rust4sap_policy::audit::AuditLog;

fn path(tag: &str) -> String {
    format!("/tmp/audit-int-{}-{tag}.jsonl", std::process::id())
}

#[test]
fn an_empty_file_starts_a_new_chain() {
    let p = path("empty");
    let _ = std::fs::remove_file(&p);
    std::fs::write(&p, "").unwrap();
    let mut log = AuditLog::open(&p).expect("empty file is a new chain");
    let e = log.append("clerk", "Read", "A_BusinessPartner", true, "ok").unwrap();
    assert_eq!(e.seq, 1);
    let _ = std::fs::remove_file(p);
}

#[test]
fn a_valid_chain_continues_where_it_left_off() {
    let p = path("valid");
    let _ = std::fs::remove_file(&p);
    let mut first = AuditLog::open(&p).unwrap();
    first.append("clerk", "Read", "A", true, "ok").unwrap();
    first.append("clerk", "Read", "A", false, "no").unwrap();
    drop(first);

    let mut second = AuditLog::open(&p).unwrap();
    let e = second.append("controller", "Read", "A", true, "ok").unwrap();
    assert_eq!(e.seq, 3, "sequence must continue, not restart");
    assert!(rust4sap_policy::audit::verify(&p).is_ok());
    let _ = std::fs::remove_file(p);
}

#[test]
fn a_torn_final_record_refuses_to_open_and_leaves_the_file_untouched() {
    let p = path("torn");
    let _ = std::fs::remove_file(&p);
    let mut log = AuditLog::open(&p).unwrap();
    log.append("clerk", "Read", "A", true, "ok").unwrap();
    drop(log);
    // simulate a partially written final line
    let mut body = std::fs::read_to_string(&p).unwrap();
    body.push_str("{\"seq\":2,\"at_unix\":\"");
    std::fs::write(&p, &body).unwrap();
    let before = std::fs::read(&p).unwrap();

    let err = match AuditLog::open(&p) {
        Ok(_) => panic!("a torn tail must be refused"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("audit_integrity"), "{err}");
    assert_eq!(std::fs::read(&p).unwrap(), before, "the file must not be truncated or repaired");
    let _ = std::fs::remove_file(p);
}

#[test]
fn a_torn_record_after_valid_records_is_not_treated_as_a_fresh_log() {
    let p = path("torn2");
    let _ = std::fs::remove_file(&p);
    let mut log = AuditLog::open(&p).unwrap();
    log.append("clerk", "Read", "A", true, "ok").unwrap();
    log.append("clerk", "Read", "A", true, "ok").unwrap();
    drop(log);
    let mut body = std::fs::read_to_string(&p).unwrap();
    body.push_str("{\"seq\":3,");
    std::fs::write(&p, &body).unwrap();

    let err = match AuditLog::open(&p) { Ok(_) => panic!("must refuse"), Err(e) => e };
    assert!(err.to_string().contains("audit_integrity"), "{err}");
    let _ = std::fs::remove_file(p);
}

#[test]
fn a_valid_final_record_after_a_corrupt_earlier_one_still_refuses() {
    // this is the case that "parse only the last line" would have missed
    let p = path("tamper");
    let _ = std::fs::remove_file(&p);
    let mut log = AuditLog::open(&p).unwrap();
    log.append("clerk", "Read", "A", true, "ok").unwrap();
    log.append("clerk", "Read", "A", true, "ok").unwrap();
    drop(log);

    let mut lines: Vec<String> = std::fs::read_to_string(&p).unwrap().lines().map(str::to_string).collect();
    // rewrite the middle entry without fixing its hash; the last entry stays syntactically valid
    let mut first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    first["subject"] = serde_json::json!("attacker");
    lines[0] = serde_json::to_string(&first).unwrap();
    std::fs::write(&p, lines.join("\n") + "\n").unwrap();

    let err = match AuditLog::open(&p) { Ok(_) => panic!("a corrupt middle entry must be refused"), Err(e) => e };
    assert!(err.to_string().contains("audit_integrity"), "{err}");
    let _ = std::fs::remove_file(p);
}

#[test]
fn verification_is_streaming_and_scales_without_loading_the_file() {
    // 20k entries: verifies from a reader, one line at a time
    let p = path("stream");
    let _ = std::fs::remove_file(&p);
    let mut log = AuditLog::open(&p).unwrap();
    for i in 0..20_000 {
        log.append("clerk", "Read", "A_BusinessPartner", i % 2 == 0, "ok").unwrap();
    }
    drop(log);

    let f = std::fs::File::open(&p).unwrap();
    let report = rust4sap_policy::audit::verify_reader(std::io::BufReader::new(f)).expect("streams");
    assert_eq!(report.entries, 20_000);
    assert_eq!(report.last_seq, 20_000);
    assert_eq!(report.versions, vec![2]);

    // reopening continues the chain from the streamed tail
    let mut again = AuditLog::open(&p).unwrap();
    let e = again.append("clerk", "Read", "A", true, "ok").unwrap();
    assert_eq!(e.seq, 20_001);
    let _ = std::fs::remove_file(p);
}
