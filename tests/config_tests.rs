use ssh_knock::config::{Config, validate_ipset_name};

fn valid_config() -> Config {
    toml::from_str(
        r#"
listen = "0.0.0.0"
ssh_port = 10022
ipset_name = "ssh_allow"
sequence_window = 5
ip_timeout = 10
partial_state_timeout = 10
max_payload_size = 512
log_level = "info"

[[knock.sequence]]
protocol = "udp"
port = 40101
size = 64

[[knock.sequence]]
protocol = "udp"
port = 40102
size = 128

[[knock.sequence]]
protocol = "udp"
port = 40103
size = 96
"#,
    )
    .expect("test fixture must parse")
}

#[test]
fn accepts_valid_configuration_because_daemon_needs_safe_startup_inputs() {
    let config = valid_config();
    assert!(config.validate().is_ok());
}

#[test]
fn rejects_short_sequences_because_single_packets_are_too_easy_to_guess() {
    let mut config = valid_config();
    config.knock.sequence.truncate(2);
    assert!(config.validate().is_err());
}

#[test]
fn rejects_duplicate_ports_because_sequence_steps_must_be_unambiguous() {
    let mut config = valid_config();
    config.knock.sequence[1].port = config.knock.sequence[0].port;
    assert!(config.validate().is_err());
}

#[test]
fn rejects_oversized_steps_because_large_packets_must_not_drive_processing() {
    let mut config = valid_config();
    config.knock.sequence[0].size = 513;
    assert!(config.validate().is_err());
}

#[test]
fn rejects_shell_metacharacters_in_ipset_name_because_firewall_commands_use_config_values() {
    assert!(validate_ipset_name("ssh_allow").is_ok());
    assert!(validate_ipset_name("ssh_allow;rm").is_err());
}
