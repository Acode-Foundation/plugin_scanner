//! `plugin_scanner update`: replaces the running binary with a release build.
//!
//! Everything goes through the GitHub API (the release, then its assets), and
//! downloads use `curl` (or `wget`), so the scanner doesn't need an HTTP/TLS
//! stack of its own. Each binary is checked against the `.sha256` published
//! next to it (and GitHub's own digest) and run once (`--version`) before it
//! is moved over the current executable, so a bad download never replaces a
//! working CLI.

use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use sha2::{Digest, Sha256};

const REPO: &str = "Acode-Foundation/plugin_scanner";
const CURRENT: &str = env!("CARGO_PKG_VERSION");

pub struct Options {
    /// Only report whether an update exists.
    pub check: bool,
    /// Install this release tag instead of the latest one.
    pub version: Option<String>,
    /// Reinstall even when already on that version.
    pub force: bool,
}

pub fn run(options: Options) -> Result<(), String> {
    let target = release_target()?;
    let release = fetch_release(options.version.as_deref())?;
    let tag = release["tag_name"]
        .as_str()
        .ok_or("GitHub returned no release tag")?
        .to_string();
    let shown = tag.trim_start_matches('v').to_string();
    let newer = is_newer(&tag, CURRENT);
    let same = parse_version(&tag) == parse_version(CURRENT);

    if options.check {
        if newer {
            println!("Update available: {CURRENT} -> {shown}. Run `plugin_scanner update`.");
        } else {
            println!("plugin_scanner {CURRENT} is up to date (latest release: {shown}).");
        }
        return Ok(());
    }
    if same && !options.force {
        println!("plugin_scanner {CURRENT} is already installed. Use --force to reinstall.");
        return Ok(());
    }
    if !newer && options.version.is_none() && !options.force {
        println!(
            "plugin_scanner {CURRENT} is newer than the latest release ({shown}); nothing to do."
        );
        return Ok(());
    }

    let exe = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| format!("cannot find the running executable: {error}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", exe.display()))?;

    let name = format!("plugin_scanner-{tag}-{target}");
    let asset = find_asset(&release, &name)
        .ok_or_else(|| format!("release {tag} has no build for {target} ({name})"))?;
    let checksum_asset = find_asset(&release, &format!("{name}.sha256"))
        .ok_or_else(|| format!("release {tag} has no checksum for {name}"))?;
    println!("Downloading {name}…");
    let binary = download_asset(asset)?;
    let checksum = download_asset(checksum_asset)?;
    verify_checksum(&binary, &checksum)?;
    // GitHub records its own digest of every upload; check that too.
    if let Some(digest) = asset["digest"]
        .as_str()
        .and_then(|digest| digest.strip_prefix("sha256:"))
    {
        verify_checksum(&binary, digest.as_bytes())?;
    }

    // Same directory as the executable, so the final rename is atomic.
    let staged = dir.join(format!(".plugin_scanner-update-{}", std::process::id()));
    let result = install(&binary, &staged, &exe, &tag);
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result?;
    println!("Updated {} from {CURRENT} to {shown}.", exe.display());
    Ok(())
}

fn install(binary: &[u8], staged: &Path, exe: &Path, tag: &str) -> Result<(), String> {
    let mut file = fs::File::create(staged).map_err(|error| permission_hint(exe, error))?;
    file.write_all(binary)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write {}: {error}", staged.display()))?;
    drop(file);
    set_executable(staged)?;

    let output = Command::new(staged)
        .arg("--version")
        .output()
        .map_err(|error| format!("the downloaded binary does not run here: {error}"))?;
    let reported = String::from_utf8_lossy(&output.stdout);
    let expected = tag.trim_start_matches('v');
    if !output.status.success() || !reported.contains(expected) {
        return Err(format!(
            "the downloaded binary reported {:?} instead of {expected}; not installing it",
            reported.trim()
        ));
    }

    fs::rename(staged, exe).map_err(|error| permission_hint(exe, error))
}

fn permission_hint(exe: &Path, error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        format!(
            "no permission to replace {}; run the update with sudo or reinstall it somewhere you own",
            exe.display()
        )
    } else {
        format!("cannot replace {}: {error}", exe.display())
    }
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("cannot mark {} executable: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// The target triple of the release build for this machine.
fn release_target() -> Result<&'static str, String> {
    target_for(std::env::consts::OS, std::env::consts::ARCH).ok_or_else(|| {
        format!(
            "no prebuilt release for {}-{}; update with `cargo install --git https://github.com/{REPO} --force`",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })
}

fn target_for(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        _ => None,
    }
}

/// The latest release, or the one tagged `version`.
fn fetch_release(version: Option<&str>) -> Result<serde_json::Value, String> {
    let url = match version {
        Some(version) => format!(
            "https://api.github.com/repos/{REPO}/releases/tags/{}",
            normalize_tag(version)
        ),
        None => format!("https://api.github.com/repos/{REPO}/releases/latest"),
    };
    let body =
        download(&url, &["Accept: application/vnd.github+json"]).map_err(
            |error| match version {
                Some(version) if error.contains("404") => {
                    format!("no release {} found for {REPO}", normalize_tag(version))
                }
                _ => error,
            },
        )?;
    serde_json::from_slice(&body)
        .map_err(|error| format!("unexpected response from GitHub: {error}"))
}

fn find_asset<'r>(release: &'r serde_json::Value, name: &str) -> Option<&'r serde_json::Value> {
    release["assets"]
        .as_array()?
        .iter()
        .find(|asset| asset["name"].as_str() == Some(name))
}

fn download_asset(asset: &serde_json::Value) -> Result<Vec<u8>, String> {
    let url = asset["url"]
        .as_str()
        .ok_or("GitHub returned an asset without a download URL")?;
    download(url, &["Accept: application/octet-stream"])
}

fn normalize_tag(version: &str) -> String {
    format!("v{}", version.trim().trim_start_matches('v'))
}

fn parse_version(version: &str) -> Option<Vec<u64>> {
    let core = version.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next()?;
    core.split('.').map(|part| part.parse().ok()).collect()
}

fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some(candidate), Some(current)) => candidate > current,
        _ => false,
    }
}

/// `<hex>  <name>` as written by `shasum -a 256`.
fn verify_checksum(binary: &[u8], checksum_file: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(checksum_file);
    let expected = text
        .split_whitespace()
        .next()
        .filter(|hex| hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or("the published .sha256 file is malformed")?
        .to_ascii_lowercase();
    let actual: String = Sha256::digest(binary)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "checksum mismatch (expected {expected}, got {actual}); not installing"
        ))
    }
}

/// Fetches a URL with curl, falling back to wget.
fn download(url: &str, headers: &[&str]) -> Result<Vec<u8>, String> {
    let user_agent = format!("plugin_scanner/{CURRENT}");
    let mut curl = vec![
        "-fsSL".to_string(),
        "--proto".into(),
        "=https".into(),
        "-A".into(),
        user_agent.clone(),
    ];
    let mut wget = vec![
        "-q".to_string(),
        "-O".into(),
        "-".into(),
        "-U".into(),
        user_agent,
    ];
    for header in headers {
        curl.extend(["-H".to_string(), header.to_string()]);
        wget.push(format!("--header={header}"));
    }
    curl.push(url.to_string());
    wget.push(url.to_string());
    let attempts = [("curl", curl), ("wget", wget)];
    let mut missing = Vec::new();
    for (tool, args) in attempts {
        match Command::new(tool).args(&args).stdin(Stdio::null()).output() {
            Ok(output) if output.status.success() => return Ok(output.stdout),
            Ok(output) => {
                return Err(format!(
                    "download failed ({url}): {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            Err(_) => missing.push(tool),
        }
    }
    Err(format!("updating needs {} on PATH", missing.join(" or ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions() {
        assert!(is_newer("v0.4.0", "0.3.0"));
        assert!(is_newer("v0.10.0", "0.9.9"));
        assert!(!is_newer("v0.3.0", "0.3.0"));
        assert!(!is_newer("v0.2.1", "0.3.0"));
        assert!(!is_newer("nightly", "0.3.0"));
        assert_eq!(parse_version("v1.2.3-rc.1"), Some(vec![1, 2, 3]));
        assert_eq!(normalize_tag("0.4.0"), "v0.4.0");
        assert_eq!(normalize_tag("v0.4.0"), "v0.4.0");
    }

    #[test]
    fn maps_platforms_to_release_targets() {
        assert_eq!(target_for("macos", "aarch64"), Some("aarch64-apple-darwin"));
        assert_eq!(
            target_for("linux", "x86_64"),
            Some("x86_64-unknown-linux-gnu")
        );
        assert_eq!(target_for("windows", "x86_64"), None);
    }

    #[test]
    fn verifies_checksums() {
        let binary = b"hello";
        let sum = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(verify_checksum(binary, format!("{sum}  plugin_scanner-v1\n").as_bytes()).is_ok());
        assert!(verify_checksum(b"other", sum.as_bytes()).is_err());
        assert!(verify_checksum(binary, b"not a checksum").is_err());
    }
}
