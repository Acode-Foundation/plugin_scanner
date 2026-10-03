//! plugin.json handling that mirrors Acode's installer and the acode.app
//! publish checks (`server/apis/plugin.js`).

use serde_json::{Map, Value};

use crate::{
    archive::{ArchiveFile, PluginArchive, extension, sanitize_zip_path},
    report::{Finding, PluginSummary, Report},
    severity::{Category, Severity},
};

const MAX_ICON_BYTES: usize = 50 * 1024;
const MIN_PRICE: f64 = 10.0;
const MAX_PRICE: f64 = 10_000.0;

#[derive(Debug, Clone, Default)]
pub struct PluginManifest {
    pub id: Option<String>,
    pub name: Option<String>,
    pub main: Option<String>,
    pub version: Option<String>,
    pub min_version_code: Option<i64>,
    pub price: Option<f64>,
    pub permissions: Vec<String>,
    pub dependencies: Vec<String>,
    pub repository: Option<String>,
    /// Installed path of the script Acode will load.
    pub entry: Option<String>,
}

impl PluginManifest {
    pub fn summary(&self) -> PluginSummary {
        PluginSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            version: self.version.clone(),
            main: self.main.clone(),
            entry: self.entry.clone(),
            min_version_code: self.min_version_code,
            price: self.price,
            permissions: self.permissions.clone(),
            dependencies: self.dependencies.clone(),
            repository: self.repository.clone(),
        }
    }
}

pub fn load(archive: &PluginArchive, report: &mut Report) -> Option<PluginManifest> {
    // The installer reads `zip.files["plugin.json"]`, an exact-key lookup.
    let Some(file) = archive.by_key("plugin.json") else {
        report.push(manifest_finding(
            "manifest.missing",
            Severity::Critical,
            "Archive has no top-level plugin.json; Acode refuses to install it",
            "plugin.json must be at the zip root, not inside a folder",
        ));
        return None;
    };

    let object = match serde_json::from_slice::<Value>(strip_bom(&file.bytes)) {
        Ok(Value::Object(object)) => object,
        Ok(_) => {
            report.push(manifest_finding(
                "manifest.invalid_json",
                Severity::Critical,
                "plugin.json is not a JSON object",
                "expected `{ ... }`",
            ));
            return None;
        }
        Err(error) => {
            report.push(manifest_finding(
                "manifest.invalid_json",
                Severity::Critical,
                "plugin.json is not valid JSON",
                error.to_string(),
            ));
            return None;
        }
    };

    let mut manifest = PluginManifest {
        id: string_field(&object, "id"),
        name: string_field(&object, "name"),
        main: string_field(&object, "main"),
        version: string_field(&object, "version"),
        min_version_code: object.get("minVersionCode").and_then(Value::as_i64),
        price: object.get("price").and_then(Value::as_f64),
        permissions: string_list(&object, "permissions"),
        dependencies: string_list(&object, "dependencies"),
        repository: match object.get("repository") {
            Some(Value::String(url)) => Some(url.clone()),
            Some(Value::Object(repo)) => string_field(repo, "url"),
            _ => None,
        },
        entry: None,
    };

    validate_fields(&object, &manifest, report);
    manifest.entry = resolve_entry(&manifest, archive, report);
    validate_assets(&object, archive, report);

    if !manifest.dependencies.is_empty() {
        report.push(
            manifest_finding(
                "manifest.dependencies",
                Severity::Low,
                "Installing this plugin also installs other plugins",
                manifest.dependencies.join(", "),
            )
            .keyed(manifest.dependencies.join(",")),
        );
    }

    Some(manifest)
}

/// Same logic as installPlugin.js: use `main` if that exact key exists,
/// otherwise fall back to `main.js`, otherwise the install fails.
fn resolve_entry(
    manifest: &PluginManifest,
    archive: &PluginArchive,
    report: &mut Report,
) -> Option<String> {
    let main = manifest.main.as_deref();
    let key = match main {
        Some(main) if archive.by_key(main).is_some() => main,
        _ if archive.by_key("main.js").is_some() => {
            if let Some(main) = main {
                report.push(manifest_finding(
                    "manifest.main_fallback",
                    Severity::Info,
                    "`main` isn't in the zip under that exact name, so Acode loads main.js",
                    format!("main = {main:?}"),
                ));
            }
            "main.js"
        }
        _ => {
            report.push(manifest_finding(
                "manifest.no_entrypoint",
                Severity::Critical,
                "Neither `main` nor main.js exists in the zip; Acode refuses to install it",
                format!("main = {:?}", main.unwrap_or("(missing)")),
            ));
            return None;
        }
    };

    if !matches!(extension(key).as_str(), "js" | "mjs" | "cjs") {
        report.push(manifest_finding(
            "manifest.non_js_entry",
            Severity::Medium,
            "Entry script doesn't have a .js extension",
            key.to_string(),
        ));
    }
    Some(sanitize_zip_path(key))
}

fn validate_fields(object: &Map<String, Value>, manifest: &PluginManifest, report: &mut Report) {
    for field in ["id", "name", "main", "version"] {
        if string_field(object, field).is_none_or(|value| value.trim().is_empty()) {
            report.push(manifest_finding(
                format!("manifest.missing_{field}"),
                if field == "main" {
                    Severity::Medium
                } else {
                    Severity::High
                },
                format!("plugin.json is missing `{field}`"),
                "required by acode.app",
            ));
        }
    }

    if let Some(id) = manifest.id.as_deref()
        && !is_valid_id(id)
    {
        report.push(manifest_finding(
            "manifest.invalid_id",
            Severity::Medium,
            "Plugin id doesn't match acode.app's rule `^[a-z][a-z0-9._]{3,49}$`",
            id.to_string(),
        ));
    }

    if let Some(version) = manifest.version.as_deref()
        && !is_valid_version(version)
    {
        report.push(manifest_finding(
            "manifest.invalid_version",
            Severity::Medium,
            "Version must be `x.y.z` digits to publish on acode.app",
            version.to_string(),
        ));
    }

    if let Some(value) = object.get("minVersionCode")
        && !value.is_i64()
    {
        report.push(manifest_finding(
            "manifest.invalid_min_version_code",
            Severity::Medium,
            "minVersionCode must be a number",
            value.to_string(),
        ));
    }

    if let Some(price) = manifest.price
        && price != 0.0
        && !(MIN_PRICE..=MAX_PRICE).contains(&price)
    {
        report.push(manifest_finding(
            "manifest.invalid_price",
            Severity::Medium,
            "Price must be between ₹10 and ₹10000 on acode.app",
            price.to_string(),
        ));
    }
}

fn validate_assets(object: &Map<String, Value>, archive: &PluginArchive, report: &mut Report) {
    // The installer patches missing icon/readme to these defaults, and the
    // website rejects uploads where neither exists.
    let icon = asset(object, archive, "icon", "icon.png");
    match icon {
        None => report.push(manifest_finding(
            "manifest.missing_icon",
            Severity::Medium,
            "No icon found (checked `icon` and icon.png); acode.app rejects the upload",
            "add icon.png",
        )),
        Some(file) if file.bytes.len() > MAX_ICON_BYTES => report.push(manifest_finding(
            "manifest.icon_too_large",
            Severity::Low,
            "Icon is larger than the documented 50 KB limit",
            format!("{}: {} bytes", file.path, file.bytes.len()),
        )),
        Some(_) => {}
    }

    if asset(object, archive, "readme", "readme.md").is_none()
        && archive.by_key("README.md").is_none()
    {
        report.push(manifest_finding(
            "manifest.missing_readme",
            Severity::Medium,
            "No readme found (checked `readme` and readme.md); acode.app rejects the upload",
            "add readme.md",
        ));
    }
}

fn asset<'a>(
    object: &Map<String, Value>,
    archive: &'a PluginArchive,
    field: &str,
    fallback: &str,
) -> Option<&'a ArchiveFile> {
    string_field(object, field)
        .and_then(|path| archive.by_key(&path))
        .or_else(|| archive.by_key(fallback))
}

fn manifest_finding(
    id: impl Into<String>,
    severity: Severity,
    message: impl Into<String>,
    evidence: impl Into<String>,
) -> Finding {
    Finding::new(id, severity, Category::Manifest, message, evidence).with_file("plugin.json")
}

fn string_field(object: &Map<String, Value>, field: &str) -> Option<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn string_list(object: &Map<String, Value>, field: &str) -> Vec<String> {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes)
}

fn is_valid_id(id: &str) -> bool {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let rest = chars.as_str();
    first.is_ascii_alphabetic()
        && (3..=49).contains(&rest.len())
        && rest
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_')
}

fn is_valid_version(version: &str) -> bool {
    let parts: Vec<_> = version.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;
    use crate::archive::Limits;

    fn load_zip(files: &[(&str, &[u8])]) -> (Option<PluginManifest>, Report) {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            for (name, bytes) in files {
                writer
                    .start_file(*name, SimpleFileOptions::default())
                    .unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.set_position(0);
        let mut report = Report::new();
        let archive = PluginArchive::from_reader(cursor, Limits::default(), &mut report).unwrap();
        (load(&archive, &mut report), report)
    }

    const ICON: (&str, &[u8]) = ("icon.png", b"\x89PNG");
    const README: (&str, &[u8]) = ("readme.md", b"# x");

    #[test]
    fn accepts_valid_manifest() {
        let (manifest, report) = load_zip(&[
            (
                "plugin.json",
                br#"{"id":"com.example.ok","name":"Ok","main":"dist/main.js","version":"1.0.0"}"#,
            ),
            ("dist/main.js", b""),
            ICON,
            README,
        ]);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(manifest.unwrap().entry.as_deref(), Some("dist/main.js"));
    }

    #[test]
    fn dot_slash_main_falls_back_to_main_js_like_installer() {
        let (manifest, report) = load_zip(&[
            (
                "plugin.json",
                br#"{"id":"com.example.ok","name":"Ok","main":"./dist/main.js","version":"1.0.0"}"#,
            ),
            ("dist/main.js", b"good"),
            ("main.js", b"other"),
            ICON,
            README,
        ]);
        assert!(report.has("manifest.main_fallback"));
        assert_eq!(manifest.unwrap().entry.as_deref(), Some("main.js"));
    }

    #[test]
    fn missing_entry_is_install_failure() {
        let (_, report) = load_zip(&[(
            "plugin.json",
            br#"{"id":"com.example.ok","name":"Ok","main":"dist/main.js","version":"1.0.0"}"#,
        )]);
        assert!(report.has("manifest.no_entrypoint"));
        assert!(report.has("manifest.missing_icon"));
        assert!(report.has("manifest.missing_readme"));
    }

    #[test]
    fn nested_plugin_json_is_not_found() {
        let (manifest, report) = load_zip(&[("my-plugin/plugin.json", b"{}")]);
        assert!(manifest.is_none());
        assert!(report.has("manifest.missing"));
    }

    #[test]
    fn wrong_field_types_do_not_abort_parsing() {
        let (manifest, report) = load_zip(&[
            (
                "plugin.json",
                br#"{"id":"x","name":"X","main":"main.js","version":"1.0","minVersionCode":"290","permissions":["net"]}"#,
            ),
            ("main.js", b""),
            ICON,
            README,
        ]);
        let manifest = manifest.unwrap();
        assert_eq!(manifest.permissions, vec!["net"]);
        assert!(report.has("manifest.invalid_id"));
        assert!(report.has("manifest.invalid_version"));
        assert!(report.has("manifest.invalid_min_version_code"));
    }
}
