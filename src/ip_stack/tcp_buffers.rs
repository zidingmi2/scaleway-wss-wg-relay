//! Capacity accounting for lazily growing userspace TCP buffers.
//!
//! The base allocation for every allowed flow is unavailable to growth. A
//! busy flow therefore cannot consume the memory needed to admit small flows.
//! Replacement allocations reserve their full size while the old storage is
//! still alive, not merely the eventual capacity difference.

use crate::{
    config::tun::TunResourceLimits,
    resources::{Budget, BudgetPermit},
};
use parking_lot::Mutex;
use std::sync::Arc;

pub(crate) const SOCKET_RECV: usize = 0;
pub(crate) const SOCKET_SEND: usize = 1;
pub(crate) const BRIDGE_RECV: usize = 2;
pub(crate) const BRIDGE_SEND: usize = 3;
const BUFFER_COUNT: usize = 4;

/// Buffers below this size quadruple per growth round; larger ones double.
/// Chosen so the 32 KiB base reaches 512 KiB in two rounds and the 4 MiB
/// maximum in five, keeping the transient replacement charge bounded near
/// the top of the range.
const GROW_QUADRUPLE_LIMIT: usize = 512 * 1024;

pub(crate) struct TcpBufferPool {
    initial: usize,
    maximum: usize,
    slots: Arc<Budget>,
    growth: Arc<Budget>,
}

impl TcpBufferPool {
    /// `limits.validate()` must have succeeded before constructing the pool.
    pub(crate) fn from_limits(limits: &TunResourceLimits) -> Option<Arc<Self>> {
        let maximum = limits.tcp_buffer_max_size?;
        let slots = limits.max_tcp_connections?;
        let total = limits.tcp_memory_bytes?;
        let reserved_base = slots
            .checked_mul(BUFFER_COUNT)?
            .checked_mul(limits.tcp_buffer_size)?;
        let growth = total.checked_sub(reserved_base)?;
        Some(Arc::new(Self {
            initial: limits.tcp_buffer_size,
            maximum,
            slots: Arc::new(Budget::new(Some(slots))),
            growth: Arc::new(Budget::new(Some(growth))),
        }))
    }

    pub(crate) fn admit(self: &Arc<Self>) -> Option<Arc<TcpBufferAllocation>> {
        let slot = self.slots.acquire(1)?;
        Some(Arc::new(TcpBufferAllocation {
            pool: self.clone(),
            state: Mutex::new(AllocationState {
                capacities: [self.initial; BUFFER_COUNT],
                progress_at_attempt: [0; BUFFER_COUNT],
                growth: None,
            }),
            _slot: slot,
        }))
    }
}

struct AllocationState {
    capacities: [usize; BUFFER_COUNT],
    progress_at_attempt: [u64; BUFFER_COUNT],
    growth: Option<BudgetPermit>,
}

/// Kept alive by both the stack entry and its async connection control. In
/// particular, removing a socket does not prematurely release queued bytes
/// still owned by an outstanding async handle.
pub(crate) struct TcpBufferAllocation {
    pool: Arc<TcpBufferPool>,
    state: Mutex<AllocationState>,
    _slot: BudgetPermit,
}

impl TcpBufferAllocation {
    pub(crate) fn maximum(&self) -> usize {
        self.pool.maximum
    }

    /// Grow one pressure-limited buffer by one tier. The closure must either
    /// replace storage with exactly `new_capacity` bytes and return true, or
    /// preserve the old storage and return false. No shrinking occurs here.
    pub(crate) fn grow_if_needed(
        &self,
        buffer: usize,
        used: usize,
        resize: impl FnOnce(usize) -> bool,
    ) -> bool {
        let mut state = self.state.lock();
        let old = state.capacities[buffer];
        if old >= self.pool.maximum || used < old.saturating_mul(3) / 4 {
            return false;
        }
        self.try_grow_locked(&mut state, buffer, resize)
    }

    /// A quickly drained receive queue can stay almost empty even when its
    /// small advertised window is the throughput bottleneck. Advance one tier
    /// after a full current-capacity of newly delivered bytes, independently
    /// of queue occupancy. A denied allocation consumes that checkpoint too,
    /// so idle polling cannot retry it without additional stream progress.
    pub(crate) fn grow_for_progress(
        &self,
        buffer: usize,
        total_progress: u64,
        resize: impl FnOnce(usize) -> bool,
    ) -> bool {
        let mut state = self.state.lock();
        let old = state.capacities[buffer];
        if old >= self.pool.maximum
            || total_progress.saturating_sub(state.progress_at_attempt[buffer]) < old as u64
        {
            return false;
        }
        state.progress_at_attempt[buffer] = total_progress;
        self.try_grow_locked(&mut state, buffer, resize)
    }

    fn try_grow_locked(
        &self,
        state: &mut AllocationState,
        buffer: usize,
        resize: impl FnOnce(usize) -> bool,
    ) -> bool {
        let old = state.capacities[buffer];
        // Quadruple while small so a long-delayed path reaches a useful window
        // in a couple of growth rounds instead of seven doublings (a ~350 ms
        // Paris↔Sydney RTT makes each round cost a full window of bytes).
        // Double above that so the transient replacement charge stays bounded
        // near the maximum.
        let factor = if old < GROW_QUADRUPLE_LIMIT { 4 } else { 2 };
        let new = old.saturating_mul(factor).min(self.pool.maximum);
        // The old allocation remains charged until `resize` has finished.
        let Some(mut temporary) = self.pool.growth.acquire(new) else {
            return false;
        };
        if !resize(new) {
            return false;
        }
        // Keep only the net growth after the old allocation was released.
        drop(temporary.split(old));
        if let Some(existing) = &mut state.growth {
            existing.merge(temporary);
        } else {
            state.growth = Some(temporary);
        }
        state.capacities[buffer] = new;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> TunResourceLimits {
        TunResourceLimits {
            tcp_buffer_size: 32 * 1024,
            tcp_buffer_max_size: Some(1024 * 1024),
            tcp_memory_bytes: Some(32 * 1024 * 1024),
            max_tcp_connections: Some(80),
            ..Default::default()
        }
    }

    #[test]
    fn growth_cannot_spend_eighty_flows_base_reservation() {
        let limits = limits();
        limits.validate().unwrap();
        let pool = TcpBufferPool::from_limits(&limits).unwrap();
        let mut flows = Vec::new();
        // Grow early arrivals before later admissions, as real traffic does.
        for _ in 0..80 {
            let flow = pool
                .admit()
                .expect("base capacity is reserved for every flow");
            for buffer in 0..BUFFER_COUNT {
                while flow.grow_if_needed(buffer, usize::MAX, |_| true) {}
            }
            flows.push(flow);
        }
        assert!(pool.admit().is_none());
        assert_eq!(pool.slots.snapshot().active, 80);
        let snapshot = pool.growth.snapshot();
        assert!(snapshot.peak + 80 * 4 * 32 * 1024 <= 32 * 1024 * 1024);
        drop(flows);
        assert_eq!(pool.slots.snapshot().active, 0);
        assert_eq!(pool.growth.snapshot().active, 0);
        assert!(pool.admit().is_some());
    }

    #[test]
    fn replacement_counts_old_and_new_capacity_and_failed_growth_releases_credit() {
        let limits = TunResourceLimits {
            tcp_buffer_size: 1024,
            tcp_buffer_max_size: Some(4096),
            tcp_memory_bytes: Some(8192),
            max_tcp_connections: Some(1),
            ..Default::default()
        };
        let pool = TcpBufferPool::from_limits(&limits).unwrap();
        let flow = pool.admit().unwrap();
        assert!(!flow.grow_if_needed(SOCKET_RECV, 1024, |new| {
            assert_eq!(new, 4096);
            assert_eq!(pool.growth.snapshot().active, 4096);
            false
        }));
        assert_eq!(pool.growth.snapshot().active, 0);
        assert!(flow.grow_if_needed(SOCKET_RECV, 1024, |_| true));
        assert_eq!(pool.growth.snapshot().active, 3072);
        assert!(!flow.grow_if_needed(SOCKET_SEND, 1024, |_| panic!("no transient capacity")));
        drop(flow);
        assert_eq!(pool.growth.snapshot().active, 0);
    }

    #[test]
    fn outstanding_async_owner_keeps_capacity_and_admission_charged() {
        let mut limits = limits();
        limits.max_tcp_connections = Some(1);
        let pool = TcpBufferPool::from_limits(&limits).unwrap();
        let stack_owner = pool.admit().unwrap();
        let async_owner = stack_owner.clone();
        assert!(stack_owner.grow_if_needed(BRIDGE_SEND, usize::MAX, |_| true));
        drop(stack_owner);
        assert!(pool.admit().is_none());
        assert_ne!(pool.growth.snapshot().active, 0);
        drop(async_owner);
        assert_eq!(pool.growth.snapshot().active, 0);
        assert!(pool.admit().is_some());
    }

    #[test]
    fn progress_growth_is_tiered_and_does_not_retry_without_new_bytes() {
        let pool = TcpBufferPool::from_limits(&limits()).unwrap();
        let flow = pool.admit().unwrap();
        assert!(!flow.grow_for_progress(SOCKET_RECV, 32767, |_| panic!("insufficient progress")));
        assert!(flow.grow_for_progress(SOCKET_RECV, 32768, |capacity| capacity == 131072));
        assert!(
            !flow.grow_for_progress(SOCKET_RECV, 32768 + 131071, |_| panic!(
                "next tier requires new bytes"
            ))
        );
        let attempts = std::cell::Cell::new(0);
        assert!(!flow.grow_for_progress(SOCKET_RECV, 32768 + 131072, |_| {
            attempts.set(attempts.get() + 1);
            false
        }));
        for _ in 0..8 {
            assert!(!flow.grow_for_progress(SOCKET_RECV, 32768 + 131072, |_| {
                attempts.set(attempts.get() + 1);
                true
            }));
        }
        assert_eq!(attempts.get(), 1);
        assert!(
            flow.grow_for_progress(SOCKET_RECV, 32768 + 2 * 131072, |capacity| capacity
                == 524288)
        );
        assert!(pool.growth.snapshot().peak + 80 * 4 * 32768 <= 32 * 1024 * 1024);
    }
}
