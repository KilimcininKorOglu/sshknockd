use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use ssh_knock::config::Config;
use ssh_knock::firewall::{Firewall, SystemCommandRunner};
use ssh_knock::server::Server;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Parser)]
#[command(name = "sshknockd")]
#[command(about = "Server-side SSH port knocking daemon")]
struct Args {
    #[arg(short, long, default_value = "/etc/sshknock.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<CommandKind>,
}

#[derive(Debug, Subcommand)]
enum CommandKind {
    SetupFirewall,
    Update,
}

/// Starts the sshknockd daemon or runs an administrative command.
///
/// # Errors
///
/// Returns an error when configuration loading, daemon startup, or firewall setup fails.
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
        None => {
            let config = Config::from_path(&args.config)?;
            let server = Server::new(config)?;
            server.run()
        }
    }
}

const GITHUB_OWNER: &str = "KilimcininKoroglu";
const GITHUB_REPO: &str = "sshknockd";

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
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
    release
        .assets
        .iter()
        .find(|asset| asset.name.ends_with(&format!(".{extension}")) && asset.name.contains(arch))
        .with_context(|| format!("release does not contain a .{extension} package for {arch}"))
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
