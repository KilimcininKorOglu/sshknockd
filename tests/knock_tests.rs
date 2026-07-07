use ssh_knock::config::{KnockStep, Protocol};
use ssh_knock::knock::{KnockOutcome, KnockPacket, KnockTracker};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

fn tracker() -> KnockTracker {
    KnockTracker::new(
        vec![
            KnockStep {
                protocol: Protocol::Udp,
                port: Some(40101),
                size: 64,
            },
            KnockStep {
                protocol: Protocol::Udp,
                port: Some(40102),
                size: 128,
            },
            KnockStep {
                protocol: Protocol::Udp,
                port: Some(40103),
                size: 96,
            },
        ],
        Duration::from_secs(5),
        Duration::from_secs(10),
        4096,
        512,
    )
}

fn bounded_tracker(max_partial_states: usize) -> KnockTracker {
    KnockTracker::new(
        vec![
            KnockStep {
                protocol: Protocol::Udp,
                port: Some(40101),
                size: 64,
            },
            KnockStep {
                protocol: Protocol::Udp,
                port: Some(40102),
                size: 128,
            },
            KnockStep {
                protocol: Protocol::Udp,
                port: Some(40103),
                size: 96,
            },
        ],
        Duration::from_secs(5),
        Duration::from_secs(10),
        max_partial_states,
        512,
    )
}

fn packet(port: u16, size: usize) -> KnockPacket {
    packet_from(Ipv4Addr::new(1, 2, 3, 4), port, size)
}

fn packet_from(source_ip: Ipv4Addr, port: u16, size: usize) -> KnockPacket {
    KnockPacket {
        source_ip: IpAddr::V4(source_ip),
        protocol: Protocol::Udp,
        port: Some(port),
        payload_size: size,
    }
}

#[test]
fn accepts_valid_sequence_because_matching_clients_need_temporary_ssh_access() {
    let mut tracker = tracker();
    let now = Instant::now();
    assert_eq!(
        tracker.process(packet(40101, 64), now),
        KnockOutcome::Progress { next_step: 1 }
    );
    assert_eq!(
        tracker.process(packet(40102, 128), now + Duration::from_secs(1)),
        KnockOutcome::Progress { next_step: 2 }
    );
    assert_eq!(
        tracker.process(packet(40103, 96), now + Duration::from_secs(2)),
        KnockOutcome::Accepted
    );
}

#[test]
fn rejects_wrong_order_because_sequence_order_is_the_shared_secret() {
    let mut tracker = tracker();
    let now = Instant::now();
    assert_eq!(
        tracker.process(packet(40102, 128), now),
        KnockOutcome::Rejected
    );
}

#[test]
fn resets_after_wrong_size_because_partial_state_must_not_survive_bad_knocks() {
    let mut tracker = tracker();
    let now = Instant::now();
    assert_eq!(
        tracker.process(packet(40101, 64), now),
        KnockOutcome::Progress { next_step: 1 }
    );
    assert_eq!(
        tracker.process(packet(40102, 127), now + Duration::from_secs(1)),
        KnockOutcome::Rejected
    );
    assert_eq!(
        tracker.process(packet(40103, 96), now + Duration::from_secs(2)),
        KnockOutcome::Rejected
    );
}

#[test]
fn rejects_expired_sequence_because_access_windows_must_be_short() {
    let mut tracker = tracker();
    let now = Instant::now();
    assert_eq!(
        tracker.process(packet(40101, 64), now),
        KnockOutcome::Progress { next_step: 1 }
    );
    assert_eq!(
        tracker.process(packet(40102, 128), now + Duration::from_secs(6)),
        KnockOutcome::Rejected
    );
}

#[test]
fn rejects_oversized_packet_because_large_payloads_must_not_drive_expensive_work() {
    let mut tracker = tracker();
    let now = Instant::now();
    assert_eq!(
        tracker.process(packet(40101, 513), now),
        KnockOutcome::Oversized
    );
}

#[test]
fn rejects_new_partial_states_at_capacity_because_incomplete_sequences_must_be_bounded() {
    let mut tracker = bounded_tracker(2);
    let now = Instant::now();

    assert_eq!(
        tracker.process(packet_from(Ipv4Addr::new(192, 0, 2, 1), 40101, 64), now),
        KnockOutcome::Progress { next_step: 1 }
    );
    assert_eq!(
        tracker.process(packet_from(Ipv4Addr::new(192, 0, 2, 2), 40101, 64), now),
        KnockOutcome::Progress { next_step: 1 }
    );
    assert_eq!(
        tracker.process(packet_from(Ipv4Addr::new(192, 0, 2, 3), 40101, 64), now),
        KnockOutcome::Rejected
    );
    assert_eq!(tracker.len(), 2);
}

#[test]
fn keeps_existing_partial_states_at_capacity_because_valid_clients_must_complete_sequences() {
    let mut tracker = bounded_tracker(2);
    let now = Instant::now();

    assert_eq!(
        tracker.process(packet_from(Ipv4Addr::new(192, 0, 2, 1), 40101, 64), now),
        KnockOutcome::Progress { next_step: 1 }
    );
    assert_eq!(
        tracker.process(packet_from(Ipv4Addr::new(192, 0, 2, 2), 40101, 64), now),
        KnockOutcome::Progress { next_step: 1 }
    );
    assert_eq!(
        tracker.process(
            packet_from(Ipv4Addr::new(192, 0, 2, 1), 40102, 128),
            now + Duration::from_secs(1)
        ),
        KnockOutcome::Progress { next_step: 2 }
    );
    assert_eq!(
        tracker.process(
            packet_from(Ipv4Addr::new(192, 0, 2, 1), 40103, 96),
            now + Duration::from_secs(2)
        ),
        KnockOutcome::Accepted
    );
}

#[test]
fn admits_new_partial_state_after_expiry_because_capacity_must_be_reusable() {
    let mut tracker = bounded_tracker(1);
    let now = Instant::now();

    assert_eq!(
        tracker.process(packet_from(Ipv4Addr::new(192, 0, 2, 1), 40101, 64), now),
        KnockOutcome::Progress { next_step: 1 }
    );
    assert_eq!(
        tracker.process(
            packet_from(Ipv4Addr::new(192, 0, 2, 2), 40101, 64),
            now + Duration::from_secs(11)
        ),
        KnockOutcome::Progress { next_step: 1 }
    );
    assert_eq!(tracker.len(), 1);
}
