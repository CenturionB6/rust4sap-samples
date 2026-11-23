//! ABAC policy: attributes in, decision out. Deny by default, deny wins.
//!
//! The engine is deliberately small and total: every request produces a `Decision`
//! with a reason and the evidence it used, because an authorisation answer without a
//! reason is impossible to audit or debug.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subject {
    pub id: String,
    pub roles: Vec<String>,
    pub region: String,
    /// 0 = external, 1 = internal, 2 = privileged
    pub clearance: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resource {
    /// OData entity set, e.g. `A_BusinessPartner`
    pub entity: String,
    /// Region the record belongs to
    pub region: String,
    /// Fields the record actually carries
    pub fields: Vec<String>,
    /// Fields that are sensitive regardless of role
    pub sensitive: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Read,
    List,
    Check,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Env {
    /// 0-23, local hour at the decision point
    pub hour: u8,
    /// e.g. "mcp-stdio", "odata"
    pub channel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub effect: Effect,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub entities: Vec<String>,
    #[serde(default)]
    pub actions: Vec<Action>,
    #[serde(default)]
    pub min_clearance: Option<u8>,
    #[serde(default)]
    pub same_region: bool,
    #[serde(default)]
    pub only_business_hours: bool,
    #[serde(default)]
    pub max_clearance: Option<u8>,
    /// Fields this rule permits; empty means "none beyond the defaults"
    #[serde(default)]
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    pub version: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
    /// Rule ids that were considered and their verdict, for the audit trail
    pub evidence: Vec<EvidencedRule>,
    pub allowed_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EvidencedRule {
    pub rule: String,
    pub effect: Effect,
    pub matched: bool,
    pub why: String,
}

impl Effect {
    fn as_str(self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
        }
    }
}

impl PolicySet {
    /// Evaluate. Any matching deny wins; otherwise the union of matching allows;
    /// otherwise deny with the reason "no rule allows".
    pub fn evaluate(&self, s: &Subject, r: &Resource, a: &Action, e: &Env) -> Decision {
        let mut evidence = Vec::new();
        let mut allowed_fields: BTreeSet<String> = BTreeSet::new();

        for rule in &self.rules {
            let (matched, why) = self.matches(rule, s, r, a, e);
            evidence.push(EvidencedRule {
                rule: rule.id.clone(),
                effect: rule.effect,
                matched,
                why: why.clone(),
            });
            if matched && rule.effect == Effect::Allow {
                for f in &rule.fields {
                    allowed_fields.insert(f.clone());
                }
            }
        }

        if let Some(deny) = evidence.iter().find(|x| x.matched && x.effect == Effect::Deny) {
            return Decision {
                allowed: false,
                reason: format!("denied by {}: {}", deny.rule, deny.why),
                evidence,
                allowed_fields: vec![],
            };
        }

        let allows: Vec<&EvidencedRule> =
            evidence.iter().filter(|x| x.matched && x.effect == Effect::Allow).collect();
        if allows.is_empty() {
            return Decision {
                allowed: false,
                reason: "no rule allows this request (deny by default)".into(),
                evidence,
                allowed_fields: vec![],
            };
        }

        Decision {
            allowed: true,
            reason: format!("allowed by {}", allows.iter().map(|x| x.rule.as_str()).collect::<Vec<_>>().join(", ")),
            evidence,
            allowed_fields: allowed_fields.into_iter().collect(),
        }
    }

    fn matches(&self, rule: &Rule, s: &Subject, r: &Resource, a: &Action, e: &Env) -> (bool, String) {
        let mut missing: Vec<String> = Vec::new();

        if !rule.roles.is_empty() && !rule.roles.iter().any(|x| s.roles.contains(x)) {
            missing.push(format!("role not in {:?}", rule.roles));
        }
        if !rule.entities.is_empty() && !rule.entities.contains(&r.entity) {
            missing.push(format!("entity {} not in {:?}", r.entity, rule.entities));
        }
        if !rule.actions.is_empty() && !rule.actions.contains(a) {
            missing.push(format!("action {:?} not permitted", a));
        }
        if let Some(min) = rule.min_clearance {
            if s.clearance < min {
                missing.push(format!("clearance {} < required {}", s.clearance, min));
            }
        }
        if let Some(max) = rule.max_clearance {
            if s.clearance > max {
                missing.push(format!("clearance {} > ceiling {}", s.clearance, max));
            }
        }
        if rule.same_region && s.region != r.region {
            missing.push(format!("region {} != record region {}", s.region, r.region));
        }
        if rule.only_business_hours && !(8..=18).contains(&e.hour) {
            missing.push(format!("hour {} outside business hours", e.hour));
        }

        if missing.is_empty() {
            (true, "all conditions met".into())
        } else {
            (false, missing.join("; "))
        }
    }
}

/// Project a record's fields onto what the decision permits, always dropping the
/// resource's sensitive fields unless the decision granted them explicitly.
pub fn filter_fields(
    record: &serde_json::Map<String, serde_json::Value>,
    decision: &Decision,
    resource: &Resource,
) -> serde_json::Map<String, serde_json::Value> {
    let permitted: BTreeSet<&str> = decision.allowed_fields.iter().map(|s| s.as_str()).collect();
    record
        .iter()
        .filter(|(k, _)| {
            let sensitive = resource.sensitive.iter().any(|s| s == *k);
            if sensitive {
                permitted.contains(k.as_str())
            } else {
                permitted.contains(k.as_str())
            }
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

// ── outcome classification ───────────────────────────────────────────────────
//
// Authorisation and redaction are different facts and are reported separately:
// `Outcome` classifies *field redaction on returned rows only*. Rows excluded by scope
// are reported by the caller (`rows_dropped`), never folded into this value — otherwise
// "Allow" would silently imply "nothing was withheld".

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    Conditional,
    Deny,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Conditional => "conditional",
            Outcome::Deny => "deny",
        }
    }
}

/// Denial outranks redaction. Redaction only refines an allow.
///
/// `any_row_redacted` is the *authorization* fact: at least one returned record lost a field.
/// It is not "row count changed" — row filtering is a separate, separately reported dimension.
pub fn outcome(allowed: bool, any_row_redacted: bool) -> Outcome {
    match (allowed, any_row_redacted) {
        (false, _) => Outcome::Deny,
        (true, true) => Outcome::Conditional,
        (true, false) => Outcome::Allow,
    }
}
