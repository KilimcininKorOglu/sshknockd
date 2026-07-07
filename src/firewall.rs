use crate::config::{AddressFamily, FirewallBackend, validate_ipset_name};
use anyhow::{Context, Result, bail};
use std::net::IpAddr;
use std::process::{Command, Output};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandStatus {
    pub success: bool,
    pub code: Option<i32>,
    pub diagnostics: String,
}

pub trait CommandRunner {
    /// Runs a command without shell interpolation and returns its exit status.
    ///
    /// # Errors
    ///
    /// Returns an error when the command fails to start.
    fn run_status(&self, spec: &CommandSpec) -> Result<CommandStatus>;

    /// Runs a command without shell interpolation.
    ///
    /// # Errors
    ///
    /// Returns an error when the command fails to start or exits unsuccessfully.
    fn run(&self, spec: &CommandSpec) -> Result<()> {
        let status = self.run_status(spec)?;
        if !status.success {
            bail!("{}", status.diagnostics);
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

const COMMAND_OUTPUT_LIMIT_BYTES: usize = 4096;

impl CommandRunner for SystemCommandRunner {
    fn run_status(&self, spec: &CommandSpec) -> Result<CommandStatus> {
        let output = Command::new(&spec.program)
            .args(&spec.args)
            .output()
            .with_context(|| format!("failed to execute {}", spec.program))?;
        Ok(CommandStatus {
            success: output.status.success(),
            code: output.status.code(),
            diagnostics: format_command_failure(spec, &output),
        })
    }
}

fn format_command_failure(spec: &CommandSpec, output: &Output) -> String {
    format!(
        "command {} exited unsuccessfully: status={}, args={:?}, stdout={:?}, stderr={:?}",
        spec.program,
        output.status,
        spec.args,
        bounded_command_output(&output.stdout),
        bounded_command_output(&output.stderr)
    )
}

fn bounded_command_output(bytes: &[u8]) -> String {
    let shown = if bytes.len() > COMMAND_OUTPUT_LIMIT_BYTES {
        &bytes[..COMMAND_OUTPUT_LIMIT_BYTES]
    } else {
        bytes
    };
    let mut text = String::from_utf8_lossy(shown).trim().to_string();
    if bytes.len() > COMMAND_OUTPUT_LIMIT_BYTES {
        text.push_str(&format!(
            " <truncated: showing first {} of {} bytes>",
            COMMAND_OUTPUT_LIMIT_BYTES,
            bytes.len()
        ));
    }
    text
}

#[derive(Debug, Clone)]
pub struct Firewall {
    ipset_name: String,
    ban_ipset_name: String,
    ip_timeout: u64,
    ban_timeout: u64,
    backend: FirewallBackend,
    address_family: AddressFamily,
}

impl Firewall {
    /// Creates a firewall integration with validated command arguments.
    ///
    /// # Errors
    ///
    /// Returns an error when the ipset name is invalid.
    pub fn new(
        ipset_name: String,
        ban_ipset_name: String,
        ip_timeout: u64,
        ban_timeout: u64,
        backend: FirewallBackend,
        address_family: AddressFamily,
    ) -> Result<Self> {
        validate_ipset_name(&ipset_name)?;
        validate_ipset_name(&ban_ipset_name)?;
        if ip_timeout == 0 || ban_timeout == 0 {
            bail!("firewall timeouts must be greater than zero");
        }
        Ok(Self {
            ipset_name,
            ban_ipset_name,
            ip_timeout,
            ban_timeout,
            backend,
            address_family,
        })
    }

    /// Returns the ipset create command for initial firewall setup.
    pub fn create_ipset_command(&self) -> CommandSpec {
        self.create_set_command(&self.ipset_name, self.ip_timeout)
    }

    /// Returns the ban ipset create command for initial firewall setup.
    pub fn create_ban_ipset_command(&self) -> CommandSpec {
        self.create_set_command(&self.ban_ipset_name, self.ban_timeout)
    }

    fn create_set_command(&self, name: &str, timeout: u64) -> CommandSpec {
        let mut args = vec![
            "create".to_string(),
            name.to_string(),
            "hash:ip".to_string(),
            "timeout".to_string(),
            timeout.to_string(),
        ];
        if self.address_family == AddressFamily::Ipv6 {
            args.push("family".to_string());
            args.push("inet6".to_string());
        }
        args.push("-exist".to_string());
        CommandSpec {
            program: "ipset".to_string(),
            args,
        }
    }

    fn firewall_program(&self) -> String {
        match self.backend {
            FirewallBackend::Iptables => "iptables".to_string(),
            FirewallBackend::Ip6tables => "ip6tables".to_string(),
        }
    }

    fn iptables_ban_drop_rule_args(&self) -> Vec<String> {
        vec![
            "-m".to_string(),
            "set".to_string(),
            "--match-set".to_string(),
            self.ban_ipset_name.clone(),
            "src".to_string(),
            "-j".to_string(),
            "DROP".to_string(),
        ]
    }

    /// Returns the firewall ban drop command for initial firewall setup.
    pub fn iptables_ban_drop_command(&self) -> CommandSpec {
        let mut args = vec!["-I".to_string(), "INPUT".to_string(), "1".to_string()];
        args.extend(self.iptables_ban_drop_rule_args());
        CommandSpec {
            program: self.firewall_program(),
            args,
        }
    }

    /// Returns the firewall ban drop check command for idempotent setup.
    pub fn iptables_ban_drop_check_command(&self) -> CommandSpec {
        let mut args = vec!["-C".to_string(), "INPUT".to_string()];
        args.extend(self.iptables_ban_drop_rule_args());
        CommandSpec {
            program: self.firewall_program(),
            args,
        }
    }

    fn iptables_allow_rule_args(&self, ssh_port: u16) -> Vec<String> {
        vec![
            "-p".to_string(),
            "tcp".to_string(),
            "--dport".to_string(),
            ssh_port.to_string(),
            "-m".to_string(),
            "set".to_string(),
            "--match-set".to_string(),
            self.ipset_name.clone(),
            "src".to_string(),
            "-j".to_string(),
            "ACCEPT".to_string(),
        ]
    }

    /// Returns the firewall allow command for initial firewall setup.
    pub fn iptables_allow_command(&self, ssh_port: u16) -> CommandSpec {
        let mut args = vec!["-I".to_string(), "INPUT".to_string(), "1".to_string()];
        args.extend(self.iptables_allow_rule_args(ssh_port));
        CommandSpec {
            program: self.firewall_program(),
            args,
        }
    }

    /// Returns the firewall allow check command for idempotent setup.
    pub fn iptables_allow_check_command(&self, ssh_port: u16) -> CommandSpec {
        let mut args = vec!["-C".to_string(), "INPUT".to_string()];
        args.extend(self.iptables_allow_rule_args(ssh_port));
        CommandSpec {
            program: self.firewall_program(),
            args,
        }
    }

    fn iptables_drop_rule_args(&self, ssh_port: u16) -> Vec<String> {
        vec![
            "-p".to_string(),
            "tcp".to_string(),
            "--dport".to_string(),
            ssh_port.to_string(),
            "-j".to_string(),
            "DROP".to_string(),
        ]
    }

    /// Returns the firewall drop command for initial firewall setup.
    pub fn iptables_drop_command(&self, ssh_port: u16) -> CommandSpec {
        let mut args = vec!["-A".to_string(), "INPUT".to_string()];
        args.extend(self.iptables_drop_rule_args(ssh_port));
        CommandSpec {
            program: self.firewall_program(),
            args,
        }
    }

    /// Returns the firewall drop check command for idempotent setup.
    pub fn iptables_drop_check_command(&self, ssh_port: u16) -> CommandSpec {
        let mut args = vec!["-C".to_string(), "INPUT".to_string()];
        args.extend(self.iptables_drop_rule_args(ssh_port));
        CommandSpec {
            program: self.firewall_program(),
            args,
        }
    }

    fn ensure_iptables_rule<R: CommandRunner>(
        &self,
        runner: &R,
        check: CommandSpec,
        apply: CommandSpec,
    ) -> Result<()> {
        let status = runner.run_status(&check)?;
        if status.success {
            return Ok(());
        }
        if status.code == Some(1) {
            return runner.run(&apply);
        }
        bail!("{}", status.diagnostics);
    }

    /// Applies the initial ipset and iptables rules.
    ///
    /// # Errors
    ///
    /// Returns an error when any firewall setup command fails.
    pub fn setup<R: CommandRunner>(&self, runner: &R, ssh_port: u16) -> Result<()> {
        runner.run(&self.create_ipset_command())?;
        runner.run(&self.create_ban_ipset_command())?;
        self.ensure_iptables_rule(
            runner,
            self.iptables_allow_check_command(ssh_port),
            self.iptables_allow_command(ssh_port),
        )?;
        self.ensure_iptables_rule(
            runner,
            self.iptables_drop_check_command(ssh_port),
            self.iptables_drop_command(ssh_port),
        )?;
        self.ensure_iptables_rule(
            runner,
            self.iptables_ban_drop_check_command(),
            self.iptables_ban_drop_command(),
        )?;
        Ok(())
    }

    /// Returns the ipset add command for a source IP.
    pub fn add_ip_command(&self, ip: IpAddr) -> CommandSpec {
        CommandSpec {
            program: "ipset".to_string(),
            args: vec![
                "add".to_string(),
                self.ipset_name.clone(),
                ip.to_string(),
                "timeout".to_string(),
                self.ip_timeout.to_string(),
                "-exist".to_string(),
            ],
        }
    }

    /// Returns the ban ipset add command for a source IP.
    pub fn ban_ip_command(&self, ip: IpAddr) -> CommandSpec {
        CommandSpec {
            program: "ipset".to_string(),
            args: vec![
                "add".to_string(),
                self.ban_ipset_name.clone(),
                ip.to_string(),
                "timeout".to_string(),
                self.ban_timeout.to_string(),
                "-exist".to_string(),
            ],
        }
    }

    /// Adds a source IP to the configured ipset.
    ///
    /// # Errors
    ///
    /// Returns an error when the ipset command fails.
    pub fn add_ip<R: CommandRunner>(&self, runner: &R, ip: IpAddr) -> Result<()> {
        runner.run(&self.add_ip_command(ip))
    }

    /// Adds a source IP to the ban ipset.
    ///
    /// # Errors
    ///
    /// Returns an error when the ban command fails.
    pub fn ban_ip<R: CommandRunner>(&self, runner: &R, ip: IpAddr) -> Result<()> {
        runner.run(&self.ban_ip_command(ip))
    }

    /// Verifies ipset and iptables availability before the daemon starts.
    ///
    /// # Errors
    ///
    /// Returns an error when required firewall tools are unavailable.
    pub fn preflight<R: CommandRunner>(&self, runner: &R) -> Result<()> {
        runner.run(&CommandSpec {
            program: "ipset".to_string(),
            args: vec!["list".to_string(), self.ipset_name.clone()],
        })?;
        runner.run(&CommandSpec {
            program: "ipset".to_string(),
            args: vec!["list".to_string(), self.ban_ipset_name.clone()],
        })?;
        runner.run(&CommandSpec {
            program: self.firewall_program(),
            args: vec!["-S".to_string()],
        })?;
        Ok(())
    }
}
