use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, VerifyingKey};
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
const CHECKSUM_MANIFEST: &str = "SHA256SUMS";
const CHECKSUM_SIGNATURE: &str = "SHA256SUMS.sig";
const CURL_CONNECT_TIMEOUT_SECS: &str = "10";
const CURL_MAX_TIME_SECS: &str = "300";
const RELEASE_SIGNING_PUBLIC_KEY: [u8; 32] = [
    0x5a, 0x2a, 0x99, 0xc1, 0x95, 0xe6, 0xeb, 0x89, 0xfb, 0xe9, 0x0c, 0xbf, 0x05, 0x19, 0x41, 0xa2,
    0x98, 0xaa, 0x75, 0xc4, 0x21, 0xf8, 0x44, 0xbb, 0xab, 0x86, 0xd7, 0x98, 0x04, 0x7d, 0x34, 0xbe,
];

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
    let manifest_asset = select_named_release_asset(&release, CHECKSUM_MANIFEST)?;
    let signature_asset = select_named_release_asset(&release, CHECKSUM_SIGNATURE)?;
    let package_path = PathBuf::from(format!("/tmp/sshknockd-update.{extension}"));
    let manifest_path = PathBuf::from("/tmp/sshknockd-SHA256SUMS");
    let signature_path = PathBuf::from("/tmp/sshknockd-SHA256SUMS.sig");
    download_package(&asset.browser_download_url, &package_path)?;
    download_package(&manifest_asset.browser_download_url, &manifest_path)?;
    download_package(&signature_asset.browser_download_url, &signature_path)?;
    verify_package_against_signed_manifest(asset, &package_path, &manifest_path, &signature_path)?;
    fs::remove_file(&manifest_path).ok();
    fs::remove_file(&signature_path).ok();
    install_package(&package_path, extension)?;
    restart_service()?;
    fs::remove_file(&package_path).ok();
    println!(
        "sshknockd updated from {} to {latest_version}",
        env!("CARGO_PKG_VERSION")
    );
    Ok(())
}

fn curl_common_args() -> [&'static str; 8] {
    [
        "--fail",
        "--location",
        "--show-error",
        "--silent",
        "--connect-timeout",
        CURL_CONNECT_TIMEOUT_SECS,
        "--max-time",
        CURL_MAX_TIME_SECS,
    ]
}

fn fetch_latest_release() -> Result<GitHubRelease> {
    let url = format!("https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest");
    let output = Command::new("curl")
        .args(curl_common_args())
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

fn select_named_release_asset<'a>(
    release: &'a GitHubRelease,
    name: &str,
) -> Result<&'a ReleaseAsset> {
    release
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .with_context(|| format!("release does not contain required asset {name}"))
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
        .args(curl_common_args())
        .arg("--output")
        .arg(package_path)
        .arg(url)
        .status()
        .context("failed to execute curl")?;
    if !status.success() {
        bail!("curl failed to download update package");
    }
    Ok(())
}

fn verify_package_against_signed_manifest(
    asset: &ReleaseAsset,
    package_path: &Path,
    manifest_path: &Path,
    signature_path: &Path,
) -> Result<()> {
    let manifest = fs::read(manifest_path).with_context(|| {
        format!(
            "failed to read checksum manifest {}",
            manifest_path.display()
        )
    })?;
    let signature = fs::read(signature_path).with_context(|| {
        format!(
            "failed to read checksum signature {}",
            signature_path.display()
        )
    })?;
    verify_manifest_signature(&manifest, &signature)?;
    let manifest =
        std::str::from_utf8(&manifest).context("checksum manifest is not valid UTF-8")?;
    let expected_hash = expected_digest_from_manifest(manifest, &asset.name)?;
    let package = fs::read(package_path).with_context(|| {
        format!(
            "failed to read downloaded package {}",
            package_path.display()
        )
    })?;
    let actual_hash = format!("{:x}", Sha256::digest(&package));
    if !actual_hash.eq_ignore_ascii_case(&expected_hash) {
        bail!(
            "downloaded package digest mismatch for {}: expected sha256:{expected_hash}, got sha256:{actual_hash}",
            asset.name
        );
    }
    Ok(())
}

fn verify_manifest_signature(manifest: &[u8], signature: &[u8]) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(&RELEASE_SIGNING_PUBLIC_KEY)
        .context("release signing public key is invalid")?;
    let signature =
        Signature::from_slice(signature).context("release checksum signature is invalid")?;
    verifying_key
        .verify_strict(manifest, &signature)
        .context("release checksum signature verification failed")
}

fn expected_digest_from_manifest(manifest: &str, package_name: &str) -> Result<String> {
    let mut matched_digest = None;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(digest) = parts.next() else {
            continue;
        };
        let Some(name) = parts.next() else {
            bail!("checksum manifest contains a malformed line");
        };
        if parts.next().is_some() {
            bail!("checksum manifest contains a malformed line");
        }
        let name = name.strip_prefix('*').unwrap_or(name);
        if name == package_name {
            validate_sha256_hex(digest)?;
            if matched_digest.replace(digest.to_string()).is_some() {
                bail!("checksum manifest contains duplicate entries for {package_name}");
            }
        }
    }
    matched_digest.with_context(|| format!("checksum manifest does not contain {package_name}"))
}

fn validate_sha256_hex(value: &str) -> Result<()> {
    if value.len() != 64 || !value.chars().all(|character| character.is_ascii_hexdigit()) {
        bail!("checksum manifest contains an invalid sha256 digest");
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

#[cfg(test)]
mod tests {
    use super::*;

    const PACKAGE_NAME: &str = "sshknockd_0.2.1_amd64.deb";
    const PACKAGE_BYTES: &[u8] = b"package bytes\n";
    const VALID_MANIFEST: &str = "40fa264148fd4b9e9bea4447cc4504f68832044997ab4921af95356d05556031  sshknockd_0.2.1_amd64.deb\n";
    const VALID_SIGNATURE: [u8; 64] = [
        0x29, 0x77, 0x17, 0xa2, 0x1d, 0x30, 0xa6, 0x68, 0xab, 0xe9, 0xff, 0x5a, 0x79, 0xc8, 0x02,
        0x1b, 0x22, 0xbf, 0x08, 0xbb, 0x6a, 0x36, 0x4f, 0x85, 0x57, 0xda, 0x38, 0xbe, 0xe4, 0x90,
        0xd0, 0x18, 0x0c, 0x8c, 0xbd, 0x28, 0x6c, 0xd7, 0xe1, 0xa1, 0xf9, 0x14, 0x1d, 0x73, 0x54,
        0x46, 0x83, 0xd7, 0x4b, 0x66, 0x17, 0x59, 0xd6, 0x30, 0x75, 0xd3, 0xd2, 0x43, 0x97, 0x44,
        0xe4, 0xa5, 0x0f, 0x07,
    ];

    #[test]
    fn common_curl_args_include_bounded_timeouts() {
        let args = curl_common_args();

        assert!(
            args.windows(2)
                .any(|pair| pair == ["--connect-timeout", CURL_CONNECT_TIMEOUT_SECS])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--max-time", CURL_MAX_TIME_SECS])
        );
        assert!(CURL_CONNECT_TIMEOUT_SECS.parse::<u64>().unwrap() > 0);
        assert!(CURL_MAX_TIME_SECS.parse::<u64>().unwrap() > 0);
    }

    #[test]
    fn verifies_manifest_signature_for_release_checksums() {
        verify_manifest_signature(VALID_MANIFEST.as_bytes(), &VALID_SIGNATURE).unwrap();
    }

    #[test]
    fn rejects_invalid_manifest_signature_before_trusting_digest() {
        let mut signature = VALID_SIGNATURE;
        signature[0] ^= 1;

        assert!(verify_manifest_signature(VALID_MANIFEST.as_bytes(), &signature).is_err());
    }

    #[test]
    fn extracts_exact_package_digest_from_manifest() {
        let digest = expected_digest_from_manifest(VALID_MANIFEST, PACKAGE_NAME).unwrap();

        assert_eq!(
            digest,
            "40fa264148fd4b9e9bea4447cc4504f68832044997ab4921af95356d05556031"
        );
    }

    #[test]
    fn rejects_missing_package_entry_in_manifest() {
        let result = expected_digest_from_manifest(VALID_MANIFEST, "missing.deb");

        assert!(result.is_err());
    }

    #[test]
    fn rejects_duplicate_package_entries_in_manifest() {
        let manifest = format!("{VALID_MANIFEST}{VALID_MANIFEST}");

        let result = expected_digest_from_manifest(&manifest, PACKAGE_NAME);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_malformed_digest_in_manifest() {
        let manifest = format!("not-a-sha256  {PACKAGE_NAME}\n");

        let result = expected_digest_from_manifest(&manifest, PACKAGE_NAME);

        assert!(result.is_err());
    }

    #[test]
    fn matches_manifest_package_name_exactly() {
        let manifest = format!(
            "40fa264148fd4b9e9bea4447cc4504f68832044997ab4921af95356d05556031  evil-{PACKAGE_NAME}\n"
        );

        let result = expected_digest_from_manifest(&manifest, PACKAGE_NAME);

        assert!(result.is_err());
    }

    #[test]
    fn detects_package_digest_mismatch_after_signed_manifest_is_valid() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join(PACKAGE_NAME);
        let manifest_path = temp.path().join(CHECKSUM_MANIFEST);
        let signature_path = temp.path().join(CHECKSUM_SIGNATURE);
        fs::write(&package_path, b"tampered package\n").unwrap();
        fs::write(&manifest_path, VALID_MANIFEST).unwrap();
        fs::write(&signature_path, VALID_SIGNATURE).unwrap();
        let asset = ReleaseAsset {
            name: PACKAGE_NAME.to_string(),
            browser_download_url: "https://example.invalid/package.deb".to_string(),
        };

        let result = verify_package_against_signed_manifest(
            &asset,
            &package_path,
            &manifest_path,
            &signature_path,
        );

        assert!(result.is_err());
    }

    #[test]
    fn accepts_package_when_signed_manifest_digest_matches() {
        let temp = tempfile::tempdir().unwrap();
        let package_path = temp.path().join(PACKAGE_NAME);
        let manifest_path = temp.path().join(CHECKSUM_MANIFEST);
        let signature_path = temp.path().join(CHECKSUM_SIGNATURE);
        fs::write(&package_path, PACKAGE_BYTES).unwrap();
        fs::write(&manifest_path, VALID_MANIFEST).unwrap();
        fs::write(&signature_path, VALID_SIGNATURE).unwrap();
        let asset = ReleaseAsset {
            name: PACKAGE_NAME.to_string(),
            browser_download_url: "https://example.invalid/package.deb".to_string(),
        };

        verify_package_against_signed_manifest(
            &asset,
            &package_path,
            &manifest_path,
            &signature_path,
        )
        .unwrap();
    }
}
