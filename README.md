# rust4sap-policy — the ABAC engine from RUST4SAP, with its tests

This is a **read-only extract**, not the gateway. It contains the policy engine and the tests
that pin its behaviour, so the security claims on the project page can be checked rather than
trusted.

```sh
cargo test     # 10 tests
```

## What is here

| file | what it is |
|---|---|
| `src/policy.rs` | the ABAC engine: deny-by-default, deny-overrides-allow, field projection |
| `src/policy.json` | the demo policy: three rules over business partners |
| `src/policy.example-strict.json` | an example with an office-hours rule |
| `tests/abac.rs` | the security tests: region isolation, clearance, deny precedence, projection |

The tests cover, among other things, that a German controller cannot read French records even
with clearance 2 — clearance buys sensitivity, not geography.

## What is deliberately not here

- identity verification, JWKS rotation, entitlements
- the MCP server and its six-tool authorization table
- the hash-chained audit log
- the SAP connector (a mock in the private repo; no SAP system has been contacted)

Those are in the private repository. Access: <mailto:centurionb6@proton.me>.

## Licence

MIT.
