# rust4sap-policy — ABAC engine, classification and audit chain from RUST4SAP

A **read-only extract**, not the gateway. It exists so the security claims on the project page can
be checked rather than trusted.

```sh
cargo test     # 37 tests
```

## What is here

| file | what it is |
|---|---|
| `src/policy.rs` | ABAC engine: deny-by-default, deny-overrides-allow, field projection as the grant |
| `src/classify.rs` | outcome classification (`allow` / `conditional` / `deny`) and metadata validation |
| `src/audit.rs` | hash-chained audit log, three format versions, streaming verification, torn-tail refusal |
| `src/policy.json` | the demo policy: three rules over business partners |
| `tests/abac.rs` | region isolation, clearance, deny precedence, field projection |
| `tests/classification.rs` | full return vs redacted vs refused; narrow records; empty scope |
| `tests/outcome.rs` | the three outcomes and their documented labels |
| `tests/audit_versions.rs` | v0/v1/v2 verification, mixed files, unknown versions refused |
| `tests/audit_integrity.rs` | torn tail refuses, corrupt middle refuses, no repair, streaming |

Concretely: a German controller cannot read French records even with clearance 2 (clearance buys
sensitivity, not geography), and a damaged audit history refuses to accept new entries.

## What is deliberately not here

- identity verification, JWKS rotation, entitlement resolution — the part that decides *who*
- the MCP server and its six-tool authorization table
- the SAP connector (a mock in the private repo; no SAP system has been contacted)

Access to the full repository: email `centurionb6 [at] proton [dot] me`.

## Licence

MIT.
