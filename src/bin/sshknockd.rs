use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use ssh_knock::config::{Config, Protocol};
use ssh_knock::firewall::{Firewall, SystemCommandRunner};
use ssh_knock::server::Server;
use std::fs;
use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "sshknockd")]
#[command(about = "Server-side SSH port knocking daemon and helper CLI")]
struct Args {
    #[arg(short, long, default_value = "/etc/sshknockd.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<CommandKind>,
}

#[derive(Debug, Subcommand)]
enum CommandKind {
    /// Create ipset sets and iptables or ip6tables rules for the protected SSH port.
    SetupFirewall,
    /// Download, install, and activate the latest package from the built-in GitHub repository.
    Update,
    /// Send the configured TCP or UDP knock sequence to the server.
    Knock {
        /// Server hostname or IP address that receives the knock sequence.
        server: String,
    },
    /// Send the configured knock sequence, then run ssh against the protected SSH port.
    Ssh {
        /// Server hostname or IP address used for the knock sequence and ssh command.
        server: String,
        /// Extra arguments passed to ssh before the server argument.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        ssh_args: Vec<String>,
    },
    /// Print shell commands that reproduce the configured knock sequence without a helper binary.
    PrintScript {
        /// Server hostname or IP address used in the generated shell commands.
        server: String,
    },
    /// Print a short summary of the loaded configuration.
    Config,
    /// Print the installed sshknockd version.
    Version,
}

/// Starts the daemon or runs an administrative or helper command.
///
/// # Errors
///
/// Returns an error when configuration loading, daemon startup, firewall setup, packet sending, or update execution fails.
fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Some(CommandKind::SetupFirewall) => {
            let config = Config::from_path(&args.config)?;
            let firewall = Firewall::new(
                config.ipset_name.clone(),
                config.ban_ipset_name.clone(),
                config.ip_timeout,
                config.ban_timeout,
                config.firewall_backend.clone(),
                config.address_family.clone(),
            )?;
            firewall.setup(&SystemCommandRunner, config.ssh_port)
        }
        Some(CommandKind::Update) => update_from_latest_release(),
        Some(CommandKind::Version) => {
            println!(env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(CommandKind::Config) => {
            let config = Config::from_path(&args.config)?;
            println!("listen={}", config.listen);
            println!("ssh_port={}", config.ssh_port);
            println!("sequence_steps={}", config.knock.sequence.len());
            Ok(())
        }
        Some(CommandKind::PrintScript { server }) => {
            let config = Config::from_path(&args.config)?;
            print_script(&config, &server)
        }
        Some(CommandKind::Knock { server }) => {
            let config = Config::from_path(&args.config)?;
            send_knock(&config, &server)
        }
        Some(CommandKind::Ssh { server, ssh_args }) => {
            let config = Config::from_path(&args.config)?;
            send_knock(&config, &server)?;
            std::thread::sleep(Duration::from_secs(1));
            let status = Command::new("ssh")
                .arg("-p")
                .arg(config.ssh_port.to_string())
                .args(ssh_args)
                .arg(&server)
                .status()
                .context("failed to execute ssh")?;
            if !status.success() {
                bail!("ssh exited unsuccessfully");
            }
            Ok(())
        }
        None => {
            let config = Config::from_path(&args.config)?;
            let server = Server::new(config)?;
            server.run()
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
            Protocol::Icmp => bail!("icmp knock sending is not supported by the helper command"),
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

const GITHUB_OWNER: &str = "KilimcininKoroglu";
const GITHUB_REPO: &str = "sshknockd";

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    digest: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
}

fn update_from_latest_release() -> Result<()> {
    let release = fetch_latest_release()?;
    let latest_version = release.tag_name.trim_start_matches('v');
    if latest_version == env!("CARGO_PKG_VERSION") {
        println!("sshknockd is already up to date at version {latest_version}");
        return Ok(());
    }
    let extension = detect_package_extension()?;
    let arch = detect_architecture()?;
    let asset = select_release_asset(&release, extension, arch)?;
    let package_path = PathBuf::from(format!("/tmp/sshknockd-update.{extension}"));
    download_package(&asset.browser_download_url, &package_path)?;
    verify_package_digest(asset, &package_path)?;
    install_package(&package_path, extension)?;
    restart_service()?;
    fs::remove_file(&package_path).ok();
    println!(
        "sshknockd updated from {} to {latest_version}",
        env!("CARGO_PKG_VERSION")
    );
    Ok(())
}

fn fetch_latest_release() -> Result<GitHubRelease> {
    let url = format!("https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest");
    let output = Command::new("curl")
        .args(["--fail", "--location", "--show-error", "--silent"])
        .args(["--header", "Accept: application/vnd.github+json"])
        .args(["--header", "X-GitHub-Api-Version: 2026-03-10"])
        .arg("--user-agent")
        .arg("sshknockd-updater")
        .arg(url)
        .output()
        .context("failed to execute curl")?;
    if !output.status.success() {
        bail!("curl failed to fetch the latest GitHub release");
    }
    serde_json::from_slice(&output.stdout).context("failed to parse GitHub release response")
}

fn detect_package_extension() -> Result<&'static str> {
    let os_release =
        fs::read_to_string("/etc/os-release").context("failed to read /etc/os-release")?;
    if os_release.contains("ID_LIKE=rhel")
        || os_release.contains("ID_LIKE=\"rhel")
        || os_release.contains("ID=centos")
        || os_release.contains("ID=fedora")
        || os_release.contains("ID=rhel")
        || os_release.contains("ID=rocky")
        || os_release.contains("ID=almalinux")
    {
        return Ok("rpm");
    }
    if os_release.contains("ID_LIKE=debian")
        || os_release.contains("ID_LIKE=\"debian")
        || os_release.contains("ID=debian")
        || os_release.contains("ID=ubuntu")
    {
        return Ok("deb");
    }
    bail!("unsupported Linux distribution for automatic package selection")
}

fn detect_architecture() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        _ => bail!("unsupported CPU architecture for automatic package selection"),
    }
}

fn select_release_asset<'a>(
    release: &'a GitHubRelease,
    extension: &str,
    arch: &str,
) -> Result<&'a ReleaseAsset> {
    let arch_names = package_arch_names(extension, arch)?;
    release
        .assets
        .iter()
        .find(|asset| {
            asset.name.ends_with(&format!(".{extension}"))
                && arch_names
                    .iter()
                    .any(|arch_name| asset.name.contains(arch_name))
        })
        .with_context(|| {
            format!(
                "release does not contain a .{extension} package for any of: {}",
                arch_names.join(", ")
            )
        })
}

fn package_arch_names(extension: &str, arch: &str) -> Result<Vec<&'static str>> {
    match (extension, arch) {
        ("deb", "amd64") => Ok(vec!["amd64"]),
        ("deb", "arm64") => Ok(vec!["arm64"]),
        ("rpm", "amd64") => Ok(vec!["x86_64"]),
        ("rpm", "arm64") => Ok(vec!["aarch64", "arm64"]),
        _ => bail!("unsupported package architecture mapping"),
    }
}

fn download_package(url: &str, package_path: &Path) -> Result<()> {
    let status = Command::new("curl")
        .args([
            "--fail",
            "--location",
            "--show-error",
            "--silent",
            "--output",
        ])
        .arg(package_path)
        .arg(url)
        .status()
        .context("failed to execute curl")?;
    if !status.success() {
        bail!("curl failed to download update package");
    }
    Ok(())
}

fn verify_package_digest(asset: &ReleaseAsset, package_path: &Path) -> Result<()> {
    let expected = asset
        .digest
        .as_deref()
        .with_context(|| format!("release asset {} does not contain a digest", asset.name))?;
    let expected_hash = expected
        .strip_prefix("sha256:")
        .with_context(|| format!("release asset {} digest is not sha256", asset.name))?;
    if expected_hash.len() != 64
        || !expected_hash
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        bail!("release asset {} has an invalid sha256 digest", asset.name);
    }

    let package = fs::read(package_path).with_context(|| {
        format!(
            "failed to read downloaded package {}",
            package_path.display()
        )
    })?;
    let actual_hash = format!("{:x}", Sha256::digest(&package));
    if !actual_hash.eq_ignore_ascii_case(expected_hash) {
        bail!(
            "downloaded package digest mismatch for {}: expected sha256:{expected_hash}, got sha256:{actual_hash}",
            asset.name
        );
    }
    Ok(())
}

fn install_package(package_path: &Path, extension: &str) -> Result<()> {
    let mut command = match extension {
        "deb" => {
            let mut command = Command::new("dpkg");
            command.arg("-i");
            command
        }
        "rpm" => {
            let mut command = Command::new("rpm");
            command.arg("-Uvh");
            command
        }
        _ => bail!("unsupported package extension"),
    };
    let status = command
        .arg(package_path)
        .status()
        .context("failed to execute package installer")?;
    if !status.success() {
        bail!("package installer exited unsuccessfully");
    }
    Ok(())
}

fn restart_service() -> Result<()> {
    let status = Command::new("systemctl")
        .args(["restart", "sshknockd"])
        .status()
        .context("failed to execute systemctl")?;
    if !status.success() {
        bail!("systemctl restart sshknockd exited unsuccessfully");
    }
    Ok(())
}
