//! Bounded IPv4 UDP fragmentation and reassembly for the rootless WG stack.
//!
//! smoltcp handles our TCP sockets, but UDP packets bypass its IP layer. Keep
//! fragmentation here so UDP never silently turns into an MTU-sized protocol.
use super::packet::PacketBuffer;
use crate::{resources::Budget, udp_budget};
use smoltcp::wire::{IpProtocol, Ipv4Packet};
use std::{
    collections::{BTreeMap, HashMap},
    io,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::{Duration, Instant},
};

pub(crate) const MAX_DATAGRAMS: usize = 32;
pub(crate) const MAX_REASSEMBLY_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_IPV4_LEN: usize = u16::MAX as usize;
// Include bounded map/permit bookkeeping rather than charging only the payload
// when a peer sends many tiny fragments.
const FRAGMENT_OVERHEAD: usize = 256;
static NEXT_IDENT: AtomicU16 = AtomicU16::new(1);

#[derive(Clone, Copy, Hash, Eq, PartialEq)]
struct Key {
    source: [u8; 4],
    target: [u8; 4],
    protocol: u8,
    identification: u16,
}

struct Fragment {
    packet: PacketBuffer,
    header_len: usize,
    end: usize,
}

struct Assembly {
    fragments: BTreeMap<usize, Fragment>,
    end: Option<usize>,
    covered: usize,
    deadline: Instant,
}

/// Completed packets retain their global/per-stack byte reservation until the
/// consumer has drained them. The reassembly-specific allowance is released
/// immediately once there is no incomplete datagram left.
pub(crate) struct Reassembler {
    assemblies: HashMap<Key, Assembly>,
    local_budget: Arc<Budget>,
    assembly_budget: Arc<Budget>,
}

impl Reassembler {
    pub(crate) fn new(local_budget: Arc<Budget>) -> Self {
        Self {
            assemblies: HashMap::new(),
            local_budget,
            assembly_budget: Arc::new(Budget::new(Some(MAX_REASSEMBLY_BYTES))),
        }
    }

    pub(crate) fn expire(&mut self, now: Instant) -> usize {
        let before = self.assemblies.len();
        self.assemblies.retain(|_, value| value.deadline > now);
        before - self.assemblies.len()
    }

    pub(crate) fn next_delay(&self, now: Instant) -> Option<Duration> {
        self.assemblies
            .values()
            .map(|entry| entry.deadline.saturating_duration_since(now))
            .min()
    }

    /// Pass nonfragmented packets through; only IPv4 UDP fragments are accepted.
    /// A protocol error invalidates the entire matching assembly.
    pub(crate) fn receive(
        &mut self,
        packet: PacketBuffer,
        now: Instant,
    ) -> io::Result<Option<PacketBuffer>> {
        self.expire(now);
        if packet.first().is_none_or(|version| version >> 4 != 4) {
            return Ok(Some(packet));
        }
        let ip = Ipv4Packet::new_checked(&*packet).map_err(|_| invalid("invalid IPv4 packet"))?;
        if !ip.verify_checksum() {
            return Err(invalid("invalid IPv4 checksum"));
        }
        let offset = usize::from(ip.frag_offset());
        let more = ip.more_frags();
        if offset == 0 && !more {
            return Ok(Some(packet));
        }
        let key = Key {
            source: ip.src_addr().octets(),
            target: ip.dst_addr().octets(),
            protocol: u8::from(ip.next_header()),
            identification: ip.ident(),
        };
        let header_len = usize::from(ip.header_len());
        let packet_len = usize::from(ip.total_len());
        let payload_len = packet_len - header_len;
        let end = offset
            .checked_add(payload_len)
            .ok_or_else(|| invalid("IPv4 fragment offset overflow"))?;
        if ip.next_header() != IpProtocol::Udp
            || ip.dont_frag()
            || packet[6] & 0x80 != 0
            || payload_len == 0
            || (more && payload_len % 8 != 0)
            || end > MAX_IPV4_LEN - 20
        {
            self.assemblies.remove(&key);
            return Err(invalid("invalid IPv4 fragment"));
        }
        if let Some(entry) = self.assemblies.get(&key) {
            // Non-overlap is an invariant, so only adjacent ranges can overlap
            // this fragment. Scanning every stored tiny fragment would permit
            // quadratic CPU consumption despite the byte budget.
            let overlaps = entry
                .fragments
                .range(..=offset)
                .next_back()
                .is_some_and(|(_, fragment)| fragment.end > offset)
                || entry
                    .fragments
                    .range(offset..)
                    .next()
                    .is_some_and(|(&start, _)| start < end);
            let contradictory_end = entry
                .end
                .is_some_and(|known| end > known || (!more && end != known));
            let greatest_end = entry
                .fragments
                .last_key_value()
                .map_or(0, |(_, fragment)| fragment.end);
            let truncates_existing = !more && greatest_end > end;
            let first_header = if offset == 0 {
                Some(header_len)
            } else {
                entry.fragments.get(&0).map(|fragment| fragment.header_len)
            };
            let maximum_end = entry.end.unwrap_or(end).max(end).max(greatest_end);
            if overlaps
                || contradictory_end
                || truncates_existing
                || first_header.is_some_and(|header| maximum_end > MAX_IPV4_LEN - header)
            {
                self.assemblies.remove(&key);
                return Err(invalid("overlapping or contradictory IPv4 fragments"));
            }
        } else if self.assemblies.len() >= MAX_DATAGRAMS {
            return Err(exhausted());
        }

        let charged = packet_len
            .checked_add(FRAGMENT_OVERHEAD)
            .ok_or_else(exhausted)?;
        let mut permits = udp_budget::reserve(&self.local_budget, charged).ok_or_else(exhausted)?;
        permits.push(
            self.assembly_budget
                .acquire(charged)
                .ok_or_else(exhausted)?,
        );
        let fragment = Fragment {
            // Compact storage prevents a tiny fragment from pinning an unrelated
            // oversized allocation from the upstream packet pool.
            packet: PacketBuffer::copy_from_slice(&packet[..packet_len])
                .with_lease(Arc::new(permits)),
            header_len,
            end,
        };
        let entry = self.assemblies.entry(key).or_insert_with(|| Assembly {
            fragments: BTreeMap::new(),
            end: None,
            covered: 0,
            deadline: now + REASSEMBLY_TIMEOUT,
        });
        if !more {
            entry.end = Some(end);
        }
        entry.fragments.insert(offset, fragment);
        entry.covered += payload_len;
        let Some(expected) = entry.end else {
            return Ok(None);
        };
        // All ranges are disjoint, nonnegative, and bounded by the known end.
        // Their summed length therefore proves completeness without rescanning
        // the map on every late fragment after the final fragment has arrived.
        if entry.covered != expected {
            return Ok(None);
        }

        let entry = self.assemblies.remove(&key).unwrap();
        let first = &entry.fragments[&0];
        let length = first.header_len + expected;
        if length > MAX_IPV4_LEN {
            return Err(invalid("reassembled IPv4 packet too large"));
        }
        // Count the temporary old-fragments + completed-packet peak before the
        // allocation. No deadline refresh from late fragments keeps abuse finite.
        let permits = udp_budget::reserve(&self.local_budget, length).ok_or_else(exhausted)?;
        let _assembly_output = self.assembly_budget.acquire(length).ok_or_else(exhausted)?;
        let mut bytes = vec![0; length];
        bytes[..first.header_len].copy_from_slice(&first.packet[..first.header_len]);
        for (start, fragment) in &entry.fragments {
            bytes[first.header_len + start..first.header_len + fragment.end]
                .copy_from_slice(&fragment.packet[fragment.header_len..]);
        }
        bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        bytes[6..8].copy_from_slice(&0u16.to_be_bytes());
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
        ip.fill_checksum();
        Ok(Some(
            PacketBuffer::from_vec(bytes).with_lease(Arc::new(permits)),
        ))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn exhausted() -> io::Error {
    io::Error::new(io::ErrorKind::OutOfMemory, "UDP fragment budget exhausted")
}

/// Bytes needed for the original complete IP packet and all output fragments
/// while the split takes place. Normal datagrams only need one packet buffer.
pub(crate) fn output_reservation(packet_len: usize, ipv4: bool, mtu: usize) -> io::Result<usize> {
    if packet_len <= mtu {
        return Ok(packet_len);
    }
    if !ipv4 || mtu < 28 || packet_len > MAX_IPV4_LEN || packet_len < 28 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP datagram cannot be fragmented",
        ));
    }
    let chunk = (mtu - 20) & !7;
    let payload = packet_len - 20;
    let count = payload.div_ceil(chunk);
    packet_len
        .checked_add(payload + count * 20)
        .ok_or_else(exhausted)
}

/// Fragment a locally constructed IPv4 UDP packet. Its UDP checksum must have
/// been computed over the complete datagram before calling this function.
pub(crate) fn split(packet: PacketBuffer, mtu: usize) -> io::Result<Vec<PacketBuffer>> {
    if packet.len() <= mtu {
        return Ok(vec![packet]);
    }
    let ip =
        Ipv4Packet::new_checked(&*packet).map_err(|_| invalid("invalid outgoing IPv4 packet"))?;
    if ip.version() != 4
        || ip.header_len() != 20
        || ip.next_header() != IpProtocol::Udp
        || ip.frag_offset() != 0
        || ip.more_frags()
        || mtu < 28
    {
        return Err(invalid("unsupported outgoing UDP packet"));
    }
    let payload = ip.payload();
    let chunk = (mtu - 20) & !7;
    let count = payload.len().div_ceil(chunk);
    let ident = NEXT_IDENT.fetch_add(1, Ordering::Relaxed);
    let mut fragments = Vec::with_capacity(count);
    for (index, data) in payload.chunks(chunk).enumerate() {
        let mut bytes = vec![0; 20 + data.len()];
        bytes[..20].copy_from_slice(&packet[..20]);
        bytes[20..].copy_from_slice(data);
        let len = bytes.len();
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
        ip.set_total_len(len as u16);
        ip.set_ident(ident);
        ip.set_dont_frag(false);
        ip.set_more_frags(index + 1 < count);
        ip.set_frag_offset((index * chunk) as u16);
        ip.fill_checksum();
        let mut fragment = PacketBuffer::from_vec(bytes);
        if let Some(lease) = packet.lease() {
            fragment = fragment.with_lease(lease)
        }
        fragments.push(fragment);
    }
    Ok(fragments)
}

#[cfg(test)]
mod tests;
