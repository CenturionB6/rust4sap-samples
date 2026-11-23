//! Extract from RUST4SAP: the ABAC policy engine, the classification rules, and the
//! hash-chained audit log — with the tests that pin their behaviour.
//!
//! Not included: identity verification, entitlements, the MCP server, connectors.
//! No key material is required to run these tests.

pub mod audit;
pub mod classify;
pub mod policy;
