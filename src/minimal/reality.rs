//! Configuration identifiers only. REALITY transport is excluded from relay builds.
#[path = "../reality/reality_cipher_suite.rs"]
mod cipher;
pub use cipher::{CipherSuite, DEFAULT_CIPHER_SUITES};
