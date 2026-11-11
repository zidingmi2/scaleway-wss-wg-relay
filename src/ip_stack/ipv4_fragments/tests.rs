use super::*;
use smoltcp::wire::UdpPacket;

fn original(size: usize) -> PacketBuffer {
    let payload: Vec<u8> = (0..size).map(|index| index as u8).collect();
    crate::tun::udp_handler::build_udp_packet(
        &payload,
        "10.77.0.1:4321".parse().unwrap(),
        "10.77.0.2:53".parse().unwrap(),
    )
    .unwrap()
}

fn rewrite_fragment(packet: &mut PacketBuffer, offset: u16, more: bool) {
    let mut ip = Ipv4Packet::new_unchecked(&mut **packet);
    ip.set_frag_offset(offset);
    ip.set_more_frags(more);
    ip.fill_checksum();
}

#[test]
fn maximum_udp_round_trip_reorders_fragments_and_verifies_checksums() {
    for length in [0, 1, 1252, 1253, 4096, 65507] {
        let expected = original(length);
        let mut fragments = split(PacketBuffer::copy_from_slice(&expected), 1280).unwrap();
        assert!(fragments.iter().all(|packet| packet.len() <= 1280));
        for fragment in &fragments {
            let ip = Ipv4Packet::new_checked(&**fragment).unwrap();
            assert!(ip.verify_checksum());
            if ip.more_frags() {
                assert_eq!(ip.payload().len() % 8, 0);
            }
        }
        fragments.reverse();
        let budget = Arc::new(Budget::new(Some(8 * 1024 * 1024)));
        let mut reassembler = Reassembler::new(budget.clone());
        let now = Instant::now();
        let mut output = None;
        for fragment in fragments {
            if let Some(packet) = reassembler.receive(fragment, now).unwrap() {
                assert!(output.replace(packet).is_none());
            }
        }
        let packet = output.unwrap();
        let ip = Ipv4Packet::new_checked(&*packet).unwrap();
        assert!(ip.verify_checksum());
        assert!(!ip.more_frags());
        assert_eq!(ip.frag_offset(), 0);
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert!(udp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
        assert_eq!(udp.payload(), &expected[28..]);
        assert_eq!(reassembler.assemblies.len(), 0);
        assert_eq!(reassembler.assembly_budget.snapshot().active, 0);
        drop(packet);
        assert_eq!(budget.snapshot().active, 0);
    }
}

#[test]
fn overlapping_or_duplicate_fragment_invalidates_whole_datagram() {
    for duplicate in [true, false] {
        let mut fragments = split(original(4096), 1280).unwrap();
        let first = fragments.remove(0);
        let mut overlap = PacketBuffer::copy_from_slice(&first);
        if !duplicate {
            rewrite_fragment(&mut overlap, 8, true);
        }
        let budget = Arc::new(Budget::new(Some(8 * 1024 * 1024)));
        let mut reassembler = Reassembler::new(budget.clone());
        let now = Instant::now();
        assert!(reassembler.receive(first, now).unwrap().is_none());
        assert!(reassembler.receive(overlap, now).is_err());
        assert!(reassembler.assemblies.is_empty());
        assert_eq!(budget.snapshot().active, 0);
    }
}

#[test]
fn missing_fragment_expires_without_refreshing_deadline() {
    let mut fragments = split(original(4096), 1280).unwrap();
    let budget = Arc::new(Budget::new(Some(8 * 1024 * 1024)));
    let mut reassembler = Reassembler::new(budget.clone());
    let now = Instant::now();
    assert!(
        reassembler
            .receive(fragments.remove(0), now)
            .unwrap()
            .is_none()
    );
    assert!(
        reassembler
            .receive(fragments.remove(0), now + Duration::from_secs(14))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reassembler.next_delay(now + Duration::from_secs(14)),
        Some(Duration::from_secs(1))
    );
    assert_eq!(reassembler.expire(now + REASSEMBLY_TIMEOUT), 1);
    assert_eq!(budget.snapshot().active, 0);
    assert!(reassembler.next_delay(now + REASSEMBLY_TIMEOUT).is_none());
}

#[test]
fn assembly_count_and_byte_limits_release_all_reservations() {
    let budget = Arc::new(Budget::new(Some(8 * 1024 * 1024)));
    let mut reassembler = Reassembler::new(budget.clone());
    let now = Instant::now();
    for _ in 0..MAX_DATAGRAMS {
        let packet = split(original(2000), 1280).unwrap().remove(0);
        assert!(reassembler.receive(packet, now).unwrap().is_none());
    }
    assert!(
        reassembler
            .receive(split(original(2000), 1280).unwrap().remove(0), now)
            .is_err()
    );
    assert_eq!(reassembler.assemblies.len(), MAX_DATAGRAMS);
    assert!(reassembler.assembly_budget.snapshot().peak <= MAX_REASSEMBLY_BYTES);
    drop(reassembler);
    assert_eq!(budget.snapshot().active, 0);

    let budget = Arc::new(Budget::new(Some(100)));
    let mut reassembler = Reassembler::new(budget.clone());
    assert!(
        reassembler
            .receive(split(original(2000), 1280).unwrap().remove(0), now)
            .is_err()
    );
    assert!(reassembler.assemblies.is_empty());
    assert_eq!(budget.snapshot().active, 0);
}

#[test]
fn incoming_peer_mtu_is_independent_of_local_transmit_mtu() {
    let fragments = split(original(5000), 1500).unwrap();
    assert!(fragments.iter().any(|packet| packet.len() > 1280));
    let mut reassembler = Reassembler::new(Arc::new(Budget::new(Some(8 * 1024 * 1024))));
    let now = Instant::now();
    let completed = fragments
        .into_iter()
        .filter_map(|fragment| reassembler.receive(fragment, now).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].len(), 5028);
}

#[test]
fn rejects_bad_checksum_non_aligned_and_overflow_fragments() {
    for invalid_case in 0..3 {
        let mut fragment = split(original(2000), 1280).unwrap().remove(0);
        match invalid_case {
            0 => fragment[10] ^= 1,
            1 => {
                let mut ip = Ipv4Packet::new_unchecked(&mut *fragment);
                ip.set_total_len(1279);
                ip.fill_checksum();
            }
            _ => rewrite_fragment(&mut fragment, 65528, true),
        }
        let mut reassembler = Reassembler::new(Arc::new(Budget::new(Some(8 * 1024 * 1024))));
        assert!(reassembler.receive(fragment, Instant::now()).is_err());
    }
}

#[test]
fn reservation_covers_original_and_all_fragments() {
    let packet = original(65507);
    let charge = output_reservation(packet.len(), true, 1280).unwrap();
    let budget = Arc::new(Budget::new(Some(charge)));
    let permit = budget.acquire(charge).unwrap();
    let packet_len = packet.len();
    let fragments = split(packet.with_lease(Arc::new(vec![permit])), 1280).unwrap();
    assert_eq!(
        charge,
        packet_len
            + fragments
                .iter()
                .map(|packet| packet.capacity())
                .sum::<usize>()
    );
    assert_eq!(budget.snapshot().active, charge);
    assert!(budget.acquire(1).is_none());
    drop(fragments);
    assert_eq!(budget.snapshot().active, 0);
}

#[test]
fn final_fragment_first_and_many_adjacent_ranges_complete_once() {
    // A deterministic small-fragment correctness case, not a traffic benchmark.
    let expected = original(1016);
    let mut fragments = split(PacketBuffer::copy_from_slice(&expected), 28).unwrap();
    assert_eq!(fragments.len(), 128);
    let budget = Arc::new(Budget::new(Some(8 * 1024 * 1024)));
    let mut reassembler = Reassembler::new(budget.clone());
    let now = Instant::now();
    assert!(
        reassembler
            .receive(fragments.pop().unwrap(), now)
            .unwrap()
            .is_none()
    );
    fragments.reverse();
    let last = fragments.pop().unwrap();
    for fragment in fragments {
        assert!(reassembler.receive(fragment, now).unwrap().is_none());
    }
    let packet = reassembler.receive(last, now).unwrap().unwrap();
    assert_eq!(&packet[20..], &expected[20..]);
    drop(packet);
    assert_eq!(budget.snapshot().active, 0);
}
