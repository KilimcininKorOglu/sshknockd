use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ssh_knock::config::{Config, Protocol};
use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "sshknock")]
#[command(about = "Optional SSHKnock helper CLI")]
struct Args {
    #[arg(short, long, default_value = "sshknock.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Debug, Subcommand)]
enum CommandKind {
    Knock {
        server: String,
    },
    Ssh {
        server: String,
        ssh_args: Vec<String>,
    },
    PrintScript {
        server: String,
    },
    Config,
    Version,
}

/// Runs the optional sshknock helper CLI.
///
/// # Errors
///
/// Returns an error when config loading, packet sending, or ssh execution fails.
fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        CommandKind::Version => {
            println!(env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        CommandKind::Config => {
            let config = Config::from_path(&args.config)?;
            println!("listen={}", config.listen);
            println!("ssh_port={}", config.ssh_port);
            println!("sequence_steps={}", config.knock.sequence.len());
            Ok(())
        }
        CommandKind::PrintScript { server } => {
            let config = Config::from_path(&args.config)?;
            print_script(&config, &server)
        }
        CommandKind::Knock { server } => {
            let config = Config::from_path(&args.config)?;
            send_knock(&config, &server)
        }
        CommandKind::Ssh { server, ssh_args } => {
            let config = Config::from_path(&args.config)?;
            send_knock(&config, &server)?;
            std::thread::sleep(Duration::from_secs(1));
            let status = Command::new("ssh")
                .arg("-p")
                .arg(config.ssh_port.to_string())
                .args(ssh_args)
                .arg(&server)
                .status()?;
            if !status.success() {
                bail!("ssh exited unsuccessfully");
            }
            Ok(())
        }
    }
}

fn send_knock(config: &Config, server: &str) -> Result<()> {
    for step in &config.knock.sequence {
        let payload = vec![b'K'; step.size];
        match step.protocol {
            Protocol::Udp => {
                let port = step.port.context("validated udp step has port")?;
                let socket = UdpSocket::bind("0.0.0.0:0")?;
                socket.send_to(&payload, (server, port))?;
            }
            Protocol::Tcp => {
                let port = step.port.context("validated tcp step has port")?;
                let mut stream = TcpStream::connect((server, port))?;
                stream.write_all(&payload)?;
            }
            Protocol::Icmp => bail!("icmp knock sending is not supported by the optional helper"),
        }
    }
    Ok(())
}

fn print_script(config: &Config, server: &str) -> Result<()> {
    for step in &config.knock.sequence {
        match step.protocol {
            Protocol::Udp => {
                let port = step.port.context("validated udp step has port")?;
                println!(
                    "printf '%0{}s' '' | tr ' ' K | nc -u -w1 {server} {port}",
                    step.size
                );
            }
            Protocol::Tcp => {
                let port = step.port.context("validated tcp step has port")?;
                println!(
                    "printf '%0{}s' '' | tr ' ' K | nc -w1 {server} {port}",
                    step.size
                );
            }
            Protocol::Icmp => {
                println!("ping -c 1 -s {} {server}", step.size);
            }
        }
    }
    println!("ssh -p {} user@{server}", config.ssh_port);
    Ok(())
}
