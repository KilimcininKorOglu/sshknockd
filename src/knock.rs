use crate::config::{KnockStep, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnockPacket {
    pub source_ip: IpAddr,
    pub protocol: Protocol,
    pub port: Option<u16>,
    pub payload_size: usize,
}

#[derive(Debug, Clone)]
struct SourceState {
    next_step: usize,
    first_seen: Instant,
    last_seen: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnockOutcome {
    Accepted,
    Progress { next_step: usize },
    Rejected,
    Oversized,
}

#[derive(Debug)]
pub struct KnockTracker {
    sequence: Vec<KnockStep>,
    sequence_window: Duration,
    partial_state_timeout: Duration,
    max_partial_states: usize,
    max_payload_size: usize,
    states: HashMap<IpAddr, SourceState>,
}

impl KnockTracker {
    /// Creates a new knock sequence tracker.
    pub fn new(
        sequence: Vec<KnockStep>,
        sequence_window: Duration,
        partial_state_timeout: Duration,
        max_partial_states: usize,
        max_payload_size: usize,
    ) -> Self {
        Self {
            sequence,
            sequence_window,
            partial_state_timeout,
            max_partial_states,
            max_payload_size,
            states: HashMap::new(),
        }
    }

    /// Returns the number of in-progress partial knock states.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Returns whether there are no in-progress partial knock states.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Processes a packet and returns whether it completed the configured sequence.
    pub fn process(&mut self, packet: KnockPacket, now: Instant) -> KnockOutcome {
        self.expire(now);
        if packet.payload_size > self.max_payload_size {
            self.states.remove(&packet.source_ip);
            return KnockOutcome::Oversized;
        }
        let expected = self
            .states
            .get(&packet.source_ip)
            .map_or(0, |state| state.next_step);
        if expected > 0
            && let Some(state) = self.states.get(&packet.source_ip)
            && now.duration_since(state.first_seen) > self.sequence_window
        {
            self.states.remove(&packet.source_ip);
            return self.start_or_reject(packet, now);
        }
        if !self.matches_step(expected, &packet) {
            self.states.remove(&packet.source_ip);
            return self.start_or_reject(packet, now);
        }
        let next_step = expected + 1;
        if next_step == self.sequence.len() {
            self.states.remove(&packet.source_ip);
            KnockOutcome::Accepted
        } else if expected == 0 {
            self.start_partial_state(packet.source_ip, now)
        } else {
            let first_seen = self
                .states
                .get(&packet.source_ip)
                .map_or(now, |state| state.first_seen);
            self.states.insert(
                packet.source_ip,
                SourceState {
                    next_step,
                    first_seen,
                    last_seen: now,
                },
            );
            KnockOutcome::Progress { next_step }
        }
    }

    /// Removes expired partial sequence state.
    pub fn expire(&mut self, now: Instant) {
        self.states.retain(|_, state| {
            now.duration_since(state.last_seen) <= self.partial_state_timeout
                && now.duration_since(state.first_seen) <= self.sequence_window
        });
    }

    fn start_or_reject(&mut self, packet: KnockPacket, now: Instant) -> KnockOutcome {
        if self.matches_step(0, &packet) {
            self.start_partial_state(packet.source_ip, now)
        } else {
            KnockOutcome::Rejected
        }
    }

    fn start_partial_state(&mut self, source_ip: IpAddr, now: Instant) -> KnockOutcome {
        if !self.states.contains_key(&source_ip) && self.states.len() >= self.max_partial_states {
            return KnockOutcome::Rejected;
        }
        self.states.insert(
            source_ip,
            SourceState {
                next_step: 1,
                first_seen: now,
                last_seen: now,
            },
        );
        KnockOutcome::Progress { next_step: 1 }
    }

    fn matches_step(&self, step_index: usize, packet: &KnockPacket) -> bool {
        let Some(step) = self.sequence.get(step_index) else {
            return false;
        };
        step.protocol == packet.protocol
            && step.port == packet.port
            && step.size == packet.payload_size
    }
}
