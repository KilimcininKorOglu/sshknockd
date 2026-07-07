use ssh_knock::config::{Config, validate_ipset_name};
use std::path::Path;

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
fn parses_example_config_because_packaged_defaults_must_remain_valid() {
    let config = Config::from_path(Path::new("sshknockd.toml"));
    assert!(config.is_ok());
}

#[test]
fn rejects_unknown_top_level_fields_because_typos_must_not_change_security_posture() {
    let result = toml::from_str::<Config>(
        r#"
listen = "0.0.0.0"
ssh_port = 10022
ipset_name = "ssh_allow"
unexpected_setting = true

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
    );

    assert!(result.is_err());
}

#[test]
fn rejects_unknown_knock_section_fields_because_nested_config_must_be_strict() {
    let result = toml::from_str::<Config>(
        r#"
listen = "0.0.0.0"
ssh_port = 10022
ipset_name = "ssh_allow"

[knock]
unexpected_section_field = true

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
    );

    assert!(result.is_err());
}

#[test]
fn rejects_unknown_knock_step_fields_because_sequence_typos_must_not_be_ignored() {
    let result = toml::from_str::<Config>(
        r#"
listen = "0.0.0.0"
ssh_port = 10022
ipset_name = "ssh_allow"

[[knock.sequence]]
protocol = "udp"
port = 40101
size = 64
unexpected_step_field = true

[[knock.sequence]]
protocol = "udp"
port = 40102
size = 128

[[knock.sequence]]
protocol = "udp"
port = 40103
size = 96
"#,
    );

    assert!(result.is_err());
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
