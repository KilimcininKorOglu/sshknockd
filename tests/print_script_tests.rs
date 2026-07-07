use anyhow::Result;
use std::process::Command;
use tempfile::NamedTempFile;

fn write_config() -> Result<NamedTempFile> {
    let config = NamedTempFile::new()?;
    std::fs::write(
        config.path(),
        r#"
listen = "0.0.0.0"
ssh_port = 10022
ipset_name = "ssh_allow"

[[knock.sequence]]
protocol = "udp"
port = 40101
size = 64

[[knock.sequence]]
protocol = "tcp"
port = 40102
size = 32

[[knock.sequence]]
protocol = "icmp"
size = 16
"#,
    )?;
    Ok(config)
}

fn run_print_script(server: &str) -> Result<std::process::Output> {
    let config = write_config()?;
    Ok(Command::new(env!("CARGO_BIN_EXE_sshknockd"))
        .arg("--config")
        .arg(config.path())
        .arg("print-script")
        .arg(server)
        .output()?)
}

#[test]
fn quotes_shell_metacharacters_because_generated_commands_must_treat_server_as_data() -> Result<()>
{
    let output = run_print_script("example.com; touch /tmp/pwned")?;

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.is_empty());
    assert!(stdout.contains("nc -u -w1 'example.com; touch /tmp/pwned' 40101"));
    assert!(stdout.contains("nc -w1 'example.com; touch /tmp/pwned' 40102"));
    assert!(stdout.contains("ping -c 1 -s 16 'example.com; touch /tmp/pwned'"));
    assert!(stdout.contains("ssh -p 10022 'user@example.com; touch /tmp/pwned'"));
    assert!(!stdout.contains("nc -u -w1 example.com; touch /tmp/pwned"));
    assert!(!stdout.contains("ssh -p 10022 user@example.com; touch /tmp/pwned"));
    Ok(())
}

#[test]
fn escapes_single_quotes_because_posix_single_quotes_must_not_terminate_the_argument() -> Result<()>
{
    let output = run_print_script("bad'host")?;

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("'bad'\\''host'"));
    assert!(stdout.contains("'user@bad'\\''host'"));
    Ok(())
}

#[test]
fn rejects_option_like_servers_because_shell_quoting_does_not_stop_command_option_injection()
-> Result<()> {
    let output = run_print_script("-e/bin/sh")?;

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("server must not start with '-'"));
    Ok(())
}

#[test]
fn rejects_control_characters_because_generated_shell_output_must_not_be_split_by_input()
-> Result<()> {
    let output = run_print_script("example.com\nid")?;

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("server must not contain control characters"));
    Ok(())
}
