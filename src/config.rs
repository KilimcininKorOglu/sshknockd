use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::fs;
use std::path::Path;

const DEFAULT_SEQUENCE_WINDOW: u64 = 5;
const DEFAULT_IP_TIMEOUT: u64 = 10;
const DEFAULT_PARTIAL_STATE_TIMEOUT: u64 = 10;
const DEFAULT_MAX_PARTIAL_STATES: usize = 4096;
const DEFAULT_MAX_PAYLOAD_SIZE: usize = 512;
const DEFAULT_INVALID_BURST_LIMIT: u32 = 20;
const DEFAULT_INVALID_REFILL_PER_MINUTE: u32 = 10;
const DEFAULT_BAN_TIMEOUT: u64 = 86_400;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallBackend {
    Iptables,
    Ip6tables,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KnockStep {
    pub protocol: Protocol,
    pub port: Option<u16>,
    pub size: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KnockSection {
    pub sequence: Vec<KnockStep>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub ssh_port: u16,
    pub ipset_name: String,
    #[serde(default = "default_firewall_backend")]
    pub firewall_backend: FirewallBackend,
    #[serde(default = "default_address_family")]
    pub address_family: AddressFamily,
    #[serde(default = "default_sequence_window")]
    pub sequence_window: u64,
    #[serde(default = "default_ip_timeout")]
    pub ip_timeout: u64,
    #[serde(default = "default_partial_state_timeout")]
    pub partial_state_timeout: u64,
    #[serde(default = "default_max_partial_states")]
    pub max_partial_states: usize,
    #[serde(default = "default_max_payload_size")]
    pub max_payload_size: usize,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_log_file")]
    pub log_file: String,
    #[serde(default = "default_invalid_burst_limit")]
    pub invalid_burst_limit: u32,
    #[serde(default = "default_invalid_refill_per_minute")]
    pub invalid_refill_per_minute: u32,
    #[serde(default = "default_ban_timeout")]
    pub ban_timeout: u64,
    #[serde(default = "default_ban_ipset_name")]
    pub ban_ipset_name: String,
    pub knock: KnockSection,
}

fn default_firewall_backend() -> FirewallBackend {
    FirewallBackend::Iptables
}

fn default_address_family() -> AddressFamily {
    AddressFamily::Ipv4
}

fn default_sequence_window() -> u64 {
    DEFAULT_SEQUENCE_WINDOW
}

fn default_ip_timeout() -> u64 {
    DEFAULT_IP_TIMEOUT
}

fn default_partial_state_timeout() -> u64 {
    DEFAULT_PARTIAL_STATE_TIMEOUT
}

fn default_max_partial_states() -> usize {
    DEFAULT_MAX_PARTIAL_STATES
}

fn default_max_payload_size() -> usize {
    DEFAULT_MAX_PAYLOAD_SIZE
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_file() -> String {
    "/var/log/sshknockd/sshknockd.log".to_string()
}

fn default_invalid_burst_limit() -> u32 {
    DEFAULT_INVALID_BURST_LIMIT
}

fn default_invalid_refill_per_minute() -> u32 {
    DEFAULT_INVALID_REFILL_PER_MINUTE
}

fn default_ban_timeout() -> u64 {
    DEFAULT_BAN_TIMEOUT
}

fn default_ban_ipset_name() -> String {
    "sshknockd_ban".to_string()
}

impl Config {
    /// Loads and validates a TOML configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, TOML parsing fails, or validation fails.
    pub fn from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let config = toml::from_str::<Self>(&raw).context("failed to parse config file")?;
        config.validate()?;
        Ok(config)
    }

    /// Validates configuration values before the daemon starts.
    ///
    /// # Errors
    ///
    /// Returns an error when a security-critical value is invalid.
    pub fn validate(&self) -> Result<()> {
        if self.knock.sequence.len() < 3 {
            bail!("knock sequence must contain at least three steps");
        }
        if self.sequence_window == 0 || self.sequence_window > 60 {
            bail!("sequence_window must be between 1 and 60 seconds");
        }
        if self.partial_state_timeout == 0 {
            bail!("partial_state_timeout must be greater than zero");
        }
        if self.max_partial_states == 0 {
            bail!("max_partial_states must be greater than zero");
        }
        if self.ip_timeout == 0 {
            bail!("ip_timeout must be greater than zero");
        }
        if self.max_payload_size == 0 {
            bail!("max_payload_size must be greater than zero");
        }
        validate_ipset_name(&self.ipset_name)?;
        validate_ipset_name(&self.ban_ipset_name)?;
        if self.invalid_burst_limit == 0 || self.invalid_refill_per_minute == 0 {
            bail!("invalid rate limit values must be greater than zero");
        }
        if self.ban_timeout == 0 {
            bail!("ban_timeout must be greater than zero");
        }
        let mut ports = Vec::new();
        for step in &self.knock.sequence {
            if step.size == 0 || step.size > self.max_payload_size {
                bail!("knock step size must be between 1 and max_payload_size");
            }
            match step.protocol {
                Protocol::Tcp | Protocol::Udp => {
                    let port = step
                        .port
                        .context("tcp and udp knock steps require a port")?;
                    if port == 0 {
                        bail!("tcp and udp knock step ports must be greater than zero");
                    }
                    if port == self.ssh_port {
                        bail!("ssh_port must not overlap knock listener ports");
                    }
                    if ports.contains(&port) {
                        bail!("knock ports must be unique within the active sequence");
                    }
                    ports.push(port);
                }
                Protocol::Icmp => {
                    if step.port.is_some() {
                        bail!("icmp knock steps must not define a port");
                    }
                }
            }
        }
        Ok(())
    }
}

/// Validates an ipset name for safe argv-based command execution.
///
/// # Errors
///
/// Returns an error when the name is empty, too long, or contains unsafe characters.
pub fn validate_ipset_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 31 {
        bail!("ipset_name length must be between 1 and 31 characters");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
    {
        bail!("ipset_name contains invalid characters");
    }
    Ok(())
}
