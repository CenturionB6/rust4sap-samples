//! Classification and metadata validation.
//!
//! Authorisation decides *whether* a request is answered; redaction describes *what was
//! withheld from the answer*. They are separate facts and are validated separately, so a
//! page can never infer one from the other.

use crate::policy::Outcome;
use std::collections::BTreeSet;

/// Bumped whenever the exported contract changes shape. The demo page refuses anything else.
pub const SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowRedaction {
    pub source_fields: usize,
    pub returned_fields: usize,
    pub redacted: bool,
}

impl RowRedaction {
    /// Redaction is a strict comparison of the same row before and after filtering —
    /// never a comparison against the policy's field universe.
    pub fn of(source: &BTreeSet<String>, returned: &BTreeSet<String>) -> Self {
        Self {
            source_fields: source.len(),
            returned_fields: returned.len(),
            redacted: returned.len() < source.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aggregate {
    /// true if any returned row lost a field
    pub any_redacted: bool,
    /// widest source row: "how many fields were on the table before filtering"
    pub fields_total: usize,
    /// unique field names that came back
    pub fields_returned: usize,
}

/// Scenario-level facts, computed from per-row metadata only.
pub fn aggregate(rows: &[RowRedaction], returned_union: &BTreeSet<String>) -> Aggregate {
    Aggregate {
        any_redacted: rows.iter().any(|r| r.redacted),
        fields_total: rows.iter().map(|r| r.source_fields).max().unwrap_or(0),
        fields_returned: returned_union.len(),
    }
}

/// The exported metadata must describe the data it ships with, or the export is wrong.
///
/// Returns the first inconsistency rather than panicking, so the binary can print it and
/// exit non-zero, and so this contract can be tested with deliberately broken input.
pub fn validate(
    allowed: bool,
    rows_returned: usize,
    rows_in_scope: usize,
    meta_len: usize,
    agg: &Aggregate,
    returned_field_names: usize,
) -> Result<(), String> {
    if allowed {
        if meta_len != rows_returned {
            return Err(format!(
                "one metadata entry per returned row: {meta_len} entries, {rows_returned} rows"
            ));
        }
        if agg.fields_returned != returned_field_names {
            return Err(format!(
                "field count {} does not match the {} unique returned names",
                agg.fields_returned, returned_field_names
            ));
        }
        if rows_returned > rows_in_scope {
            return Err(format!(
                "returned {rows_returned} rows from a scope of {rows_in_scope}"
            ));
        }
    } else {
        if rows_returned != 0 || meta_len != 0 {
            return Err("a denied request must return no rows and no metadata".into());
        }
        if agg.fields_total != 0 || agg.fields_returned != 0 || agg.any_redacted {
            return Err("a denied request has no field metadata and is not 'redacted'".into());
        }
    }
    Ok(())
}

/// The single place the three outcomes are derived.
pub fn classify(allowed: bool, any_redacted: bool) -> Outcome {
    crate::policy::outcome(allowed, any_redacted)
}
