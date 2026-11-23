//! The security claims, as tests. If these fail, the server must not ship.

use rust4sap_policy::policy::{filter_fields, Action, Decision, Env, PolicySet, Resource, Subject};
use serde_json::json;

fn policy() -> PolicySet {
    serde_json::from_str(include_str!("../src/policy.json")).unwrap()
}
fn env() -> Env { Env { hour: 10, channel: "test".into() } }
fn res(region: &str) -> Resource {
    Resource {
        entity: "A_BusinessPartner".into(),
        region: region.into(),
        fields: vec!["BusinessPartner".into(), "LastName".into(), "Region".into(), "IBAN".into()],
        sensitive: vec!["IBAN".into()],
    }
}
fn buyer(region: &str) -> Subject {
    Subject { id: "u1".into(), roles: vec!["SAP_BR_BUYER".into()], region: region.into(), clearance: 1 }
}

#[test]
fn buyer_reads_own_region() {
    let d = policy().evaluate(&buyer("DE"), &res("DE"), &Action::Read, &env());
    assert!(d.allowed, "{}", d.reason);
    assert!(d.reason.contains("buyer-de-partners"));
}

#[test]
fn buyer_cannot_read_another_region() {
    let d = policy().evaluate(&buyer("DE"), &res("FR"), &Action::Read, &env());
    assert!(!d.allowed, "same_region must hold: {}", d.reason);
}

#[test]
fn unknown_role_is_denied_by_default() {
    let nobody = Subject { id: "x".into(), roles: vec!["SAP_BR_INTERN".into()], region: "DE".into(), clearance: 1 };
    let d = policy().evaluate(&nobody, &res("DE"), &Action::Read, &env());
    assert!(!d.allowed);
    assert!(d.reason.contains("deny by default"));
    assert!(d.evidence.iter().any(|e| e.rule == "buyer-de-partners" && !e.matched));
}

#[test]
fn deny_wins_over_allow() {
    // clearance 0 is denied unconditionally, even if another rule would allow
    let mut p = policy();
    p.rules.push(serde_json::from_value(json!({
        "id": "allow-external-too", "effect": "allow", "entities": ["A_BusinessPartner"],
        "actions": ["read"], "fields": ["BusinessPartner"]
    })).unwrap());
    let ext = Subject { id: "e".into(), roles: vec![], region: "DE".into(), clearance: 0 };
    let d = p.evaluate(&ext, &res("DE"), &Action::Read, &env());
    assert!(!d.allowed, "a matching deny must beat a matching allow");
    assert!(d.reason.contains("external-no-finance"));
}

#[test]
fn controller_sees_iban_buyer_does_not() {
    let p = policy();
    let buyer_fields = p.evaluate(&buyer("DE"), &res("DE"), &Action::Read, &env()).allowed_fields;
    assert!(!buyer_fields.contains(&"IBAN".to_string()), "buyer must not get IBAN: {buyer_fields:?}");

    let controller = Subject {
        id: "c".into(), roles: vec!["SAP_BR_FIN_CONTROLLER".into()], region: "DE".into(), clearance: 2,
    };
    let cf = p.evaluate(&controller, &res("DE"), &Action::Read, &env()).allowed_fields;
    assert!(cf.contains(&"IBAN".to_string()), "controller should see IBAN: {cf:?}");
}

#[test]
fn filtering_drops_fields_outside_the_grant() {
    let d = Decision { allowed: true, reason: "t".into(), evidence: vec![],
                       allowed_fields: vec!["BusinessPartner".into(), "LastName".into()] };
    let record: serde_json::Map<String, serde_json::Value> = json!({
        "BusinessPartner": "0000100001", "LastName": "Muster", "Region": "DE",
        "IBAN": "DE00 0000 0000 0000 0001"
    }).as_object().unwrap().clone();

    let out = filter_fields(&record, &d, &res("DE"));
    assert!(out.contains_key("BusinessPartner"));
    assert!(!out.contains_key("IBAN"), "sensitive field leaked: {out:?}");
    assert!(!out.contains_key("Region"), "ungranted field leaked: {out:?}");
}

// ── F3: clearance must not widen scope ──────────────────────────────────────

#[test]
fn controller_cannot_read_across_regions() {
    let p = policy();
    let controller = Subject {
        id: "c".into(),
        roles: vec!["SAP_BR_FIN_CONTROLLER".into()],
        region: "DE".into(),
        clearance: 2,
    };
    // in-region stays allowed and still carries IBAN
    let inside = p.evaluate(&controller, &res("DE"), &Action::Read, &env());
    assert!(inside.allowed, "{}", inside.reason);
    assert!(inside.reason.contains("controller-region-partners"));
    assert!(inside.allowed_fields.contains(&"IBAN".to_string()));

    // out-of-region is denied, and the evidence says why
    let outside = p.evaluate(&controller, &res("FR"), &Action::Read, &env());
    assert!(!outside.allowed, "clearance 2 must not imply cross-region access");
    let rule = outside
        .evidence
        .iter()
        .find(|e| e.rule == "controller-region-partners")
        .expect("the controller rule must appear in the evidence");
    assert!(!rule.matched);
    assert!(rule.why.contains("region DE != record region FR"), "evidence: {}", rule.why);
}

/// The principle: higher clearance grants more sensitive data, never more scope.
///
/// Formulation note. A clearance *floor* is not a scope widening: the buyer rule has
/// `min_clearance: 1`, so at clearance 0 the role may read nothing and at clearance 1 it may
/// read its own region. That is a threshold, and comparing across it would call every
/// minimum-viable policy a violation. The property therefore compares only the clearances at
/// which the role is allowed at all: once access exists, the region scope must not grow.
///
/// Enumerated rather than random, so a failure names the exact tuple that broke it.
#[test]
fn clearance_never_widens_region_scope_once_allowed() {
    let p = policy();
    let roles = ["SAP_BR_BUYER", "SAP_BR_FIN_CONTROLLER", "SAP_BR_INTERN"];
    let subject_regions = ["DE", "FR"];
    let record_regions = ["DE", "FR", "IT"];

    for role in roles {
        for sregion in subject_regions {
            let subject_at = |c: u8| Subject {
                id: "u".into(),
                roles: vec![role.into()],
                region: sregion.into(),
                clearance: c,
            };

            let mut scopes: Vec<(u8, Vec<&'static str>)> = Vec::new();
            for c in 0..=2u8 {
                let mut allowed_regions = Vec::new();
                for r in record_regions {
                    if p.evaluate(&subject_at(c), &res(r), &Action::Read, &env()).allowed {
                        allowed_regions.push(r);
                    }
                }
                if !allowed_regions.is_empty() {
                    scopes.push((c, allowed_regions));
                }
            }

            if let Some(((first_c, first), rest)) = scopes.split_first() {
                for (c, regions) in rest {
                    assert_eq!(
                        first, regions,
                        "{role} in {sregion}: region scope changed from clearance {first_c} to {c} \
                         ({first:?} → {regions:?}); clearance may add fields, never regions"
                    );
                }
            }
        }
    }
}

/// Entity scope is a separate dimension and must behave the same way: a rule that grants one
/// entity must never, through clearance alone, begin granting another.
#[test]
fn clearance_never_widens_entity_scope() {
    let p = policy();
    let entities = ["A_BusinessPartner", "A_SalesOrder", "A_FinancialDocument"];
    for role in ["SAP_BR_BUYER", "SAP_BR_FIN_CONTROLLER"] {
        let mut scopes: Vec<(u8, Vec<&str>)> = Vec::new();
        for c in 0..=2u8 {
            let subject = Subject {
                id: "u".into(),
                roles: vec![role.into()],
                region: "DE".into(),
                clearance: c,
            };
            let mut allowed = Vec::new();
            for e in entities {
                let mut resource = res("DE");
                resource.entity = e.to_string();
                if p.evaluate(&subject, &resource, &Action::Read, &env()).allowed {
                    allowed.push(e);
                }
            }
            if !allowed.is_empty() {
                scopes.push((c, allowed));
            }
        }
        if let Some(((first_c, first), rest)) = scopes.split_first() {
            for (c, ents) in rest {
                assert_eq!(first, ents, "{role}: entity scope widened from clearance {first_c} to {c}");
            }
        }
    }
}

/// The converse, tested independently: a higher clearance must not silently *remove*
/// fields that a lower clearance was granted for the same role.
#[test]
fn clearance_never_removes_granted_fields() {
    let p = policy();
    for role in ["SAP_BR_BUYER", "SAP_BR_FIN_CONTROLLER"] {
        for sregion in ["DE", "FR"] {
            let mut previous: Option<Vec<String>> = None;
            for c in 0..=2u8 {
                let subject = Subject {
                    id: "u".into(),
                    roles: vec![role.into()],
                    region: sregion.into(),
                    clearance: c,
                };
                let d = p.evaluate(&subject, &res(sregion), &Action::Read, &env());
                if !d.allowed {
                    continue;
                }
                if let Some(prev) = &previous {
                    for f in prev {
                        assert!(
                            d.allowed_fields.contains(f),
                            "{role} in {sregion} lost field {f} at clearance {c} — \
                             removal needs an explicit policy condition, not a side effect"
                        );
                    }
                }
                previous = Some(d.allowed_fields.clone());
            }
        }
    }
}
