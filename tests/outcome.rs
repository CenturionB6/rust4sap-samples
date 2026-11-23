//! Classification is an authorization concept, so it is tested in Rust — not in the page.

use rust4sap_policy::policy::{outcome, Outcome};

#[test]
fn full_return_is_allow() {
    assert_eq!(outcome(true, false), Outcome::Allow);
}

#[test]
fn partial_redaction_is_conditional() {
    assert_eq!(outcome(true, true), Outcome::Conditional);
}

#[test]
fn denied_is_deny_regardless_of_field_metadata() {
    // even if a buggy caller passes redacted=true, a refusal stays a refusal
    assert_eq!(outcome(false, true), Outcome::Deny);
    assert_eq!(outcome(false, false), Outcome::Deny);
}

#[test]
fn labels_are_the_documented_strings() {
    assert_eq!(Outcome::Allow.as_str(), "allow");
    assert_eq!(Outcome::Conditional.as_str(), "conditional");
    assert_eq!(Outcome::Deny.as_str(), "deny");
}
