use anyhow::Result;
use ssh_knock::config::{AddressFamily, FirewallBackend};
use ssh_knock::firewall::{CommandRunner, CommandSpec, Firewall};
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
