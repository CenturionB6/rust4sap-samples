//! Classification and metadata validation — the contract the demo page relies on.

use rust4sap_policy::classify::{aggregate, classify, validate, RowRedaction, SCHEMA_VERSION};
use rust4sap_policy::policy::Outcome;
use std::collections::BTreeSet;

fn fields(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}
fn row(src: &[&str], ret: &[&str]) -> RowRedaction {
    RowRedaction::of(&fields(src), &fields(ret))
}

#[test]
fn full_return_is_allow() {
    let r = row(&["BusinessPartner", "LastName", "Region", "IBAN"],
                &["BusinessPartner", "LastName", "Region", "IBAN"]);
    assert!(!r.redacted);
    assert_eq!(classify(true, r.redacted), Outcome::Allow);
}

#[test]
fn partial_redaction_is_conditional() {
    let r = row(&["BusinessPartner", "LastName", "Region", "IBAN"],
                &["BusinessPartner", "LastName", "Region"]);
    assert!(r.redacted);
    assert_eq!(classify(true, r.redacted), Outcome::Conditional);
}

#[test]
fn denied_is_deny_regardless_of_field_metadata() {
    assert_eq!(classify(false, false), Outcome::Deny);
    assert_eq!(classify(false, true), Outcome::Deny);
}

#[test]
fn narrow_record_is_not_redacted() {
    // the record never carried IBAN, so nothing was withheld — this is an ALLOW, not conditional
    let r = row(&["BusinessPartner", "LastName", "Region"],
                &["BusinessPartner", "LastName", "Region"]);
    assert!(!r.redacted, "a 3-field record filtered to 3 fields is not redacted");
    assert_eq!(classify(true, r.redacted), Outcome::Allow);
}

#[test]
fn mixed_rows_are_conditional() {
    let rows = vec![
        row(&["A", "B", "C"], &["A", "B", "C"]),          // untouched
        row(&["A", "B", "C", "IBAN"], &["A", "B", "C"]),  // redacted
    ];
    let agg = aggregate(&rows, &fields(&["A", "B", "C"]));
    assert!(agg.any_redacted, "one redacted row makes the scenario conditional");
    assert_eq!(agg.fields_total, 4, "widest source row");
    assert_eq!(classify(true, agg.any_redacted), Outcome::Conditional);
}

#[test]
fn empty_scope_is_allow_with_no_field_metadata() {
    let agg = aggregate(&[], &fields(&[]));
    assert!(!agg.any_redacted);
    assert_eq!(agg.fields_total, 0);
    assert_eq!(agg.fields_returned, 0);
    assert_eq!(classify(true, agg.any_redacted), Outcome::Allow);
    // allowed, nothing in scope, metadata consistent
    assert!(validate(true, 0, 0, 0, &agg, 0).is_ok());
}

#[test]
fn denied_export_must_carry_no_field_metadata() {
    let agg = aggregate(&[], &fields(&[]));
    assert!(validate(false, 0, 3, 0, &agg, 0).is_ok());
    // a denial that ships rows or metadata is a contract violation
    assert!(validate(false, 1, 3, 1, &agg, 0).is_err());
    let tainted = RowRedaction { source_fields: 4, returned_fields: 3, redacted: true };
    let bad = aggregate(&[tainted], &fields(&["A"]));
    assert!(validate(false, 0, 3, 0, &bad, 1).is_err(), "a refusal is not a redaction");
}

#[test]
fn inconsistent_metadata_is_rejected() {
    let rows = vec![row(&["A", "B", "C", "D"], &["A", "B", "C"])];
    let agg = aggregate(&rows, &fields(&["A", "B", "C"]));
    // one row returned, zero metadata entries
    assert!(validate(true, 1, 1, 0, &agg, 3).is_err());
    // field count disagrees with the unique name list
    assert!(validate(true, 1, 1, 1, &agg, 99).is_err());
    // returned more rows than the scope contained
    assert!(validate(true, 2, 1, 2, &agg, 3).is_err());
    // the honest case passes
    assert!(validate(true, 1, 1, 1, &agg, 3).is_ok());
}

#[test]
fn schema_version_is_two() {
    assert_eq!(SCHEMA_VERSION, 2);
}
