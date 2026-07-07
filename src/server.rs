use crate::config::{Config, Protocol};
use crate::firewall::{CommandRunner, Firewall, SystemCommandRunner};
use crate::knock::{KnockOutcome, KnockPacket, KnockTracker};
use crate::logger::AuditLogger;
use crate::rate_limit::TokenBucketLimiter;
use anyhow::{Context, Result};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use std::collections::HashMap;
use std::io::{ErrorKind, Read};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Server {
    config: Config,
    tracker: KnockTracker,
    firewall: Firewall,
    logger: AuditLogger,
    source_limiter: TokenBucketLimiter<IpAddr>,
    packet_telemetry_limiter: TokenBucketLimiter<&'static str>,
    banned_sources: HashMap<IpAddr, Instant>,
}

impl Server {
    /// Creates a server from validated configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when firewall configuration is invalid.
    pub fn new(config: Config) -> Result<Self> {
        let tracker = KnockTracker::new(
            config.knock.sequence.clone(),
            Duration::from_secs(config.sequence_window),
            Duration::from_secs(config.partial_state_timeout),
            config.max_payload_size,
        );
        let firewall = Firewall::new(
            config.ipset_name.clone(),
            config.ban_ipset_name.clone(),
            config.ip_timeout,
            config.ban_timeout,
            config.firewall_backend.clone(),
            config.address_family.clone(),
        )?;
        let logger = AuditLogger::new(Path::new(&config.log_file))?;
        let source_burst = config.invalid_burst_limit;
        let source_refill = config.invalid_refill_per_minute;
        Ok(Self {
            config,
            tracker,
            firewall,
            logger,
            source_limiter: TokenBucketLimiter::new(
                source_burst,
                source_refill,
                Duration::from_secs(60),
            ),
            packet_telemetry_limiter: TokenBucketLimiter::new(
                source_burst.saturating_mul(10),
                source_refill.saturating_mul(10),
                Duration::from_secs(60),
            ),
            banned_sources: HashMap::new(),
        })
    }

    /// Runs knock listeners for the configured TCP, UDP, and ICMP sequence steps.
    ///
    /// # Errors
    ///
    /// Returns an error when sockets cannot bind or firewall commands fail.
    pub fn run(mut self) -> Result<()> {
        let runner = SystemCommandRunner;
        self.logger.log("daemon_start", "sshknockd starting")?;
        if let Err(error) = self.firewall.preflight(&runner) {
            self.logger
                .log("firewall_preflight_failed", &format!("error={error}"))?;
            return Err(error);
        }
        self.logger.log("firewall_preflight", "completed")?;
        let mut udp_sockets = Vec::new();
        let mut tcp_listeners = Vec::new();
        let mut icmp_socket = None;
        for step in &self.config.knock.sequence {
            match step.protocol {
                Protocol::Udp => {
                    let port = step.port.context("validated udp step has port")?;
                    if udp_sockets.iter().any(|(existing, _)| *existing == port) {
                        continue;
                    }
                    let socket = UdpSocket::bind((self.config.listen.as_str(), port))
                        .with_context(|| format!("failed to bind UDP knock port {port}"))?;
                    socket
                        .set_nonblocking(true)
                        .context("failed to configure UDP socket")?;
                    self.logger.log("bind_udp", "status=bound")?;
                    udp_sockets.push((port, socket));
                }
                Protocol::Tcp => {
                    let port = step.port.context("validated tcp step has port")?;
                    if tcp_listeners.iter().any(|(existing, _)| *existing == port) {
                        continue;
                    }
                    let listener = TcpListener::bind((self.config.listen.as_str(), port))
                        .with_context(|| format!("failed to bind TCP knock port {port}"))?;
                    listener
                        .set_nonblocking(true)
                        .context("failed to configure TCP listener")?;
                    self.logger.log("bind_tcp", "status=bound")?;
                    tcp_listeners.push((port, listener));
                }
                Protocol::Icmp => {
                    if icmp_socket.is_none() {
                        icmp_socket = Some(Self::bind_icmp_socket()?);
                        self.logger.log("bind_icmp", "enabled")?;
                    }
                }
            }
        }
        let mut buffer = vec![0_u8; self.config.max_payload_size.saturating_add(1)];
        let mut icmp_buffer =
            vec![MaybeUninit::<u8>::uninit(); self.config.max_payload_size.saturating_add(29)];
        loop {
            for (port, socket) in &udp_sockets {
                match socket.recv_from(&mut buffer) {
                    Ok((size, addr)) => {
                        self.process_packet(addr, Protocol::Udp, Some(*port), size, &runner)?;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            for (port, listener) in &tcp_listeners {
                match listener.accept() {
                    Ok((mut stream, addr)) => {
                        if let Some(size) = read_tcp_knock(
                            &mut stream,
                            &mut buffer,
                            Duration::from_secs(self.config.partial_state_timeout),
                        )? {
                            self.process_packet(addr, Protocol::Tcp, Some(*port), size, &runner)?;
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if let Some(socket) = &icmp_socket {
                match socket.recv_from(&mut icmp_buffer) {
                    Ok((size, addr)) => {
                        let addr = addr
                            .as_socket()
                            .context("failed to read ICMP source address")?;
                        let payload_size = size.saturating_sub(28);
                        self.process_packet(addr, Protocol::Icmp, None, payload_size, &runner)?;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn bind_icmp_socket() -> Result<Socket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(SocketProtocol::ICMPV4))
            .context("failed to create ICMP datagram socket")?;
        socket
            .set_nonblocking(true)
            .context("failed to configure ICMP raw socket")?;
        Ok(socket)
    }

    fn expire_banned_sources(&mut self, now: Instant) {
        self.banned_sources
            .retain(|_, expires_at| *expires_at > now);
    }

    fn is_source_banned(&mut self, source_ip: IpAddr, now: Instant) -> bool {
        self.expire_banned_sources(now);
        self.banned_sources.contains_key(&source_ip)
    }

    fn remember_banned_source(&mut self, source_ip: IpAddr, now: Instant) {
        let expires_at = now + Duration::from_secs(self.config.ban_timeout);
        self.banned_sources.insert(source_ip, expires_at);
    }

    fn packet_telemetry_enabled(&self) -> bool {
        self.config.log_level.eq_ignore_ascii_case("debug")
            || self.config.log_level.eq_ignore_ascii_case("trace")
    }

    fn redacted_outcome(outcome: &KnockOutcome) -> &'static str {
        match outcome {
            KnockOutcome::Accepted => "accepted",
            KnockOutcome::Progress { .. } => "progress",
            KnockOutcome::Rejected => "rejected",
            KnockOutcome::Oversized => "oversized",
        }
    }

    fn log_packet_telemetry(
        &mut self,
        source_ip: IpAddr,
        outcome: &KnockOutcome,
        now: Instant,
    ) -> Result<()> {
        if !self.packet_telemetry_enabled() || !self.packet_telemetry_limiter.allow("packet", now) {
            return Ok(());
        }
        self.logger
            .log("packet_seen", &format!("source_ip={source_ip} observed=true"))?;
        self.logger.log(
            "knock_outcome",
            &format!(
                "source_ip={source_ip} outcome={}",
                Self::redacted_outcome(outcome)
            ),
        )?;
        Ok(())
    }

    fn process_packet<R: CommandRunner>(
        &mut self,
        addr: SocketAddr,
        protocol: Protocol,
        port: Option<u16>,
        payload_size: usize,
        runner: &R,
    ) -> Result<()> {
        let source_ip: IpAddr = addr.ip();
        let now = Instant::now();
        if self.is_source_banned(source_ip, now) {
            return Ok(());
        }
        let outcome = self.tracker.process(
            KnockPacket {
                source_ip,
                protocol: protocol.clone(),
                port,
                payload_size,
            },
            now,
        );
        if matches!(outcome, KnockOutcome::Rejected | KnockOutcome::Oversized)
            && !self.source_limiter.allow(source_ip, now)
        {
            if let Err(error) = self.firewall.ban_ip(runner, source_ip) {
                self.logger.log(
                    "firewall_ban_failed",
                    &format!("source_ip={source_ip} error={error}"),
                )?;
                return Err(error);
            }
            self.remember_banned_source(source_ip, now);
            self.logger.log(
                "rate_limit_ban",
                &format!(
                    "source_ip={source_ip} ban_timeout_seconds={}",
                    self.config.ban_timeout
                ),
            )?;
            return Ok(());
        }
        self.log_packet_telemetry(source_ip, &outcome, now)?;
        if outcome == KnockOutcome::Accepted {
            if let Err(error) = self.firewall.add_ip(runner, source_ip) {
                self.logger.log(
                    "firewall_allow_failed",
                    &format!("source_ip={source_ip} error={error}"),
                )?;
                return Err(error);
            }
            self.logger.log(
                "ssh_allow",
                &format!(
                    "source_ip={source_ip} allow_timeout_seconds={}",
                    self.config.ip_timeout
                ),
            )?;
        }
        Ok(())
    }
}

/// Reads a TCP knock payload with a bounded timeout.
///
/// # Errors
///
/// Returns an error when timeout configuration fails or when the read fails for a reason other than timeout.
pub fn read_tcp_knock(
    stream: &mut std::net::TcpStream,
    buffer: &mut [u8],
    timeout: Duration,
) -> std::io::Result<Option<usize>> {
    stream.set_read_timeout(Some(timeout))?;
    match stream.read(buffer) {
        Ok(size) => Ok(Some(size)),
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AddressFamily, FirewallBackend, KnockSection, KnockStep};
    use crate::firewall::{CommandSpec, CommandStatus};
    use std::cell::RefCell;
    use std::fs;

    fn test_server(ban_timeout: u64) -> Result<Server> {
        let (server, _log_file) = test_server_with_log_level("info", ban_timeout)?;
        Ok(server)
    }

    fn test_server_with_log_level(
        log_level: &str,
        ban_timeout: u64,
    ) -> Result<(Server, tempfile::NamedTempFile)> {
        let log_file = tempfile::NamedTempFile::new()?;
        let config = Config {
            listen: "127.0.0.1".to_string(),
            ssh_port: 22,
            ipset_name: "ssh_allow".to_string(),
            firewall_backend: FirewallBackend::Iptables,
            address_family: AddressFamily::Ipv4,
            sequence_window: 5,
            ip_timeout: 10,
            partial_state_timeout: 10,
            max_payload_size: 512,
            log_level: log_level.to_string(),
            log_file: log_file.path().to_string_lossy().into_owned(),
            invalid_burst_limit: 1,
            invalid_refill_per_minute: 1,
            ban_timeout,
            ban_ipset_name: "ssh_ban".to_string(),
            knock: KnockSection {
                sequence: vec![
                    KnockStep {
                        protocol: Protocol::Tcp,
                        port: Some(7001),
                        size: 1,
                    },
                    KnockStep {
                        protocol: Protocol::Udp,
                        port: Some(7002),
                        size: 2,
                    },
                    KnockStep {
                        protocol: Protocol::Tcp,
                        port: Some(7003),
                        size: 3,
                    },
                ],
            },
        };

        Ok((Server::new(config)?, log_file))
    }

    #[derive(Debug, Default)]
    struct RecordingRunner {
        commands: RefCell<Vec<CommandSpec>>,
    }

    impl CommandRunner for RecordingRunner {
        fn run_status(&self, spec: &CommandSpec) -> Result<CommandStatus> {
            self.commands.borrow_mut().push(spec.clone());
            Ok(CommandStatus {
                success: true,
                code: Some(0),
                diagnostics: String::new(),
            })
        }
    }

    fn process_partial_knock(server: &mut Server, source_ip: &str) -> Result<()> {
        let addr = SocketAddr::new(source_ip.parse()?, 12_345);
        let runner = SystemCommandRunner;
        server.process_packet(addr, Protocol::Tcp, Some(7001), 1, &runner)
    }

    fn process_oversized_knock(
        server: &mut Server,
        runner: &RecordingRunner,
        source_ip: &str,
    ) -> Result<()> {
        let addr = SocketAddr::new(source_ip.parse()?, 12_345);
        server.process_packet(addr, Protocol::Tcp, Some(7001), 513, runner)
    }

    fn count_packet_telemetry(content: &str) -> usize {
        content
            .lines()
            .filter(|line| {
                line.contains("event=packet_seen") || line.contains("event=knock_outcome")
            })
            .count()
    }

    #[test]
    fn info_suppresses_packet_telemetry_because_default_logs_must_not_be_high_volume() -> Result<()>
    {
        let (mut server, log_file) = test_server_with_log_level("info", 2)?;

        process_partial_knock(&mut server, "192.0.2.10")?;

        let content = fs::read_to_string(log_file.path())?;
        assert!(!content.contains("event=packet_seen"));
        assert!(!content.contains("event=knock_outcome"));
        Ok(())
    }

    #[test]
    fn debug_writes_packet_telemetry_because_verbose_logs_need_packet_observability() -> Result<()>
    {
        let (mut server, log_file) = test_server_with_log_level("debug", 2)?;

        process_partial_knock(&mut server, "192.0.2.11")?;

        let content = fs::read_to_string(log_file.path())?;
        assert!(content.contains("event=packet_seen"));
        assert!(content.contains("event=knock_outcome"));
        assert!(content.contains("outcome=progress"));
        assert!(!content.contains("protocol="));
        assert!(!content.contains("port=7001"));
        assert!(!content.contains("size=1"));
        assert!(!content.contains("next_step"));
        assert!(!content.contains("Progress {"));
        Ok(())
    }

    #[test]
    fn trace_writes_packet_telemetry_because_trace_uses_the_verbose_packet_path() -> Result<()> {
        let (mut server, log_file) = test_server_with_log_level("trace", 2)?;

        process_partial_knock(&mut server, "192.0.2.12")?;

        let content = fs::read_to_string(log_file.path())?;
        assert!(content.contains("event=packet_seen"));
        assert!(content.contains("event=knock_outcome"));
        Ok(())
    }

    #[test]
    fn debug_packet_telemetry_is_bounded_because_packet_logs_must_not_grow_unbounded() -> Result<()>
    {
        let (mut server, log_file) = test_server_with_log_level("debug", 2)?;

        for offset in 0..12 {
            process_partial_knock(&mut server, &format!("192.0.2.{}", 20 + offset))?;
        }

        let content = fs::read_to_string(log_file.path())?;
        assert_eq!(count_packet_telemetry(&content), 20);
        Ok(())
    }

    #[test]
    fn does_not_ban_unrelated_sources_when_aggregate_invalid_traffic_is_high_because_bans_are_per_source()
    -> Result<()> {
        let mut server = test_server(2)?;
        let runner = RecordingRunner::default();

        for offset in 1..=12 {
            process_oversized_knock(&mut server, &runner, &format!("192.0.2.{offset}"))?;
        }

        assert!(server.banned_sources.is_empty());
        assert!(runner.commands.borrow().is_empty());
        Ok(())
    }

    #[test]
    fn bans_source_after_its_own_invalid_limit_is_exceeded_because_rate_limits_are_per_source()
    -> Result<()> {
        let mut server = test_server(2)?;
        let runner = RecordingRunner::default();
        let source_ip = "192.0.2.20";

        process_oversized_knock(&mut server, &runner, source_ip)?;
        process_oversized_knock(&mut server, &runner, source_ip)?;

        let parsed_source_ip = source_ip.parse()?;
        let commands = runner.commands.borrow();
        assert!(server.banned_sources.contains_key(&parsed_source_ip));
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].program, "ipset");
        assert_eq!(
            commands[0].args,
            vec![
                "add".to_string(),
                "ssh_ban".to_string(),
                source_ip.to_string(),
                "timeout".to_string(),
                "2".to_string(),
                "-exist".to_string(),
            ]
        );
        Ok(())
    }

    #[test]
    fn keeps_source_banned_before_timeout_because_rate_limit_bans_must_fail_closed() -> Result<()> {
        let mut server = test_server(2)?;
        let source_ip = "192.0.2.10".parse()?;
        let now = Instant::now();

        server.remember_banned_source(source_ip, now);

        assert!(server.is_source_banned(source_ip, now + Duration::from_secs(1)));
        Ok(())
    }

    #[test]
    fn expires_source_ban_at_timeout_because_configured_ban_duration_is_finite() -> Result<()> {
        let mut server = test_server(2)?;
        let source_ip = "192.0.2.10".parse()?;
        let now = Instant::now();

        server.remember_banned_source(source_ip, now);

        assert!(!server.is_source_banned(source_ip, now + Duration::from_secs(2)));
        Ok(())
    }

    #[test]
    fn removes_expired_source_ban_because_stale_memory_must_not_extend_ipset_timeout() -> Result<()>
    {
        let mut server = test_server(2)?;
        let source_ip = "192.0.2.10".parse()?;
        let now = Instant::now();

        server.remember_banned_source(source_ip, now);
        server.expire_banned_sources(now + Duration::from_secs(2));

        assert!(!server.banned_sources.contains_key(&source_ip));
        Ok(())
    }
}
