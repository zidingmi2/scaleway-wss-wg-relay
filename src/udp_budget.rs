//! Shared capacity accounting for the relay's UDP codecs, queues and reassembly.
//!
//! The limit is intentionally independent of a particular WireGuard stack: two
//! protocol frontends must not each allocate their own full eight MiB allowance.
use crate::resources::{Budget, BudgetPermit};
use std::sync::{Arc, LazyLock};

pub(crate) const MAX_BYTES: usize = 8 * 1024 * 1024;
static UDP_BYTES: LazyLock<Arc<Budget>> = LazyLock::new(|| Arc::new(Budget::new(Some(MAX_BYTES))));

pub(crate) fn global() -> Arc<Budget> {
    UDP_BYTES.clone()
}

/// Reserve both the shared relay allowance and an optional per-stack allowance.
/// All reservations are acquired before allocating the payload they account for.
pub(crate) fn reserve(local: &Arc<Budget>, bytes: usize) -> Option<Vec<BudgetPermit>> {
    let global = global();
    let shared = global.acquire(bytes)?;
    if Arc::ptr_eq(local, &global) {
        return Some(vec![shared]);
    }
    let local = local.acquire(bytes)?;
    Some(vec![shared, local])
}
