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
        512,
    )
}

fn packet(port: u16, size: usize) -> KnockPacket {
    KnockPacket {
        source_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
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
