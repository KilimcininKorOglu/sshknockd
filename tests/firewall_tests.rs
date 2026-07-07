use anyhow::Result;
use ssh_knock::config::{AddressFamily, FirewallBackend};
use ssh_knock::firewall::{CommandRunner, CommandSpec, Firewall, SystemCommandRunner};
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Default)]
struct RecordingRunner {
    commands: RefCell<Vec<CommandSpec>>,
}

impl CommandRunner for RecordingRunner {
    fn run(&self, spec: &CommandSpec) -> Result<()> {
        self.commands.borrow_mut().push(spec.clone());
        Ok(())
    }
}

#[cfg(unix)]
#[test]
fn system_runner_reports_status_stdout_and_stderr_because_firewall_failures_need_diagnostics() {
    let runner = SystemCommandRunner;
    let error = runner
        .run(&CommandSpec {
            program: "/bin/sh".to_string(),
            args: vec![
                "-c".to_string(),
                "printf 'visible stdout'; printf 'visible stderr' >&2; exit 7".to_string(),
            ],
        })
        .expect_err("command should fail");
    let message = error.to_string();

    assert!(message.contains("status="));
    assert!(message.contains("exit status: 7") || message.contains("7"));
    assert!(message.contains("stdout="));
    assert!(message.contains("visible stdout"));
    assert!(message.contains("stderr="));
    assert!(message.contains("visible stderr"));
}

#[cfg(unix)]
#[test]
fn system_runner_bounds_output_because_firewall_errors_must_not_be_unbounded() {
    let runner = SystemCommandRunner;
    let error = runner
        .run(&CommandSpec {
            program: "/bin/sh".to_string(),
            args: vec![
                "-c".to_string(),
                "i=0; while [ \"$i\" -lt 5000 ]; do printf o; printf e >&2; i=$((i + 1)); done; exit 9".to_string(),
            ],
        })
        .expect_err("command should fail");
    let message = error.to_string();

    assert!(message.contains("truncated"));
    assert!(message.contains("stdout="));
    assert!(message.contains("stderr="));
    assert!(message.len() < 10_000);
}

#[test]
fn builds_ipset_argv_because_shell_interpolation_must_never_be_used() {
    let firewall = Firewall::new(
        "ssh_allow".to_string(),
        "ssh_ban".to_string(),
        10,
        86_400,
        FirewallBackend::Iptables,
        AddressFamily::Ipv4,
    )
    .expect("valid firewall config");
    let command = firewall.add_ip_command(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    assert_eq!(command.program, "ipset");
    assert_eq!(
        command.args,
        vec!["add", "ssh_allow", "1.2.3.4", "timeout", "10", "-exist"]
    );
}

#[test]
fn preflights_ipset_and_iptables_because_daemon_must_fail_closed_before_listening() {
    let firewall = Firewall::new(
        "ssh_allow".to_string(),
        "ssh_ban".to_string(),
        10,
        86_400,
        FirewallBackend::Iptables,
        AddressFamily::Ipv4,
    )
    .expect("valid firewall config");
    let runner = RecordingRunner::default();
    firewall
        .preflight(&runner)
        .expect("preflight should call runner");
    let commands = runner.commands.borrow();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[0].program, "ipset");
    assert_eq!(commands[1].program, "ipset");
    assert_eq!(commands[2].program, "iptables");
}

#[test]
fn builds_ipv6_firewall_commands_because_ipv6_clients_need_matching_allow_rules() {
    let firewall = Firewall::new(
        "ssh6_allow".to_string(),
        "ssh6_ban".to_string(),
        10,
        86_400,
        FirewallBackend::Ip6tables,
        AddressFamily::Ipv6,
    )
    .expect("valid ipv6 firewall config");
    let create = firewall.create_ipset_command();
    assert_eq!(create.program, "ipset");
    assert!(create.args.contains(&"family".to_string()));
    assert!(create.args.contains(&"inet6".to_string()));
    let allow = firewall.iptables_allow_command(10022);
    assert_eq!(allow.program, "ip6tables");
    let add = firewall.add_ip_command(IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(add.args[2], "::1");
}
