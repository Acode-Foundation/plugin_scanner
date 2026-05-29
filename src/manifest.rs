use serde::Deserialize;

use crate::{
    archive::{PluginArchive, is_unsafe_path, normalize_zip_path},
    report::{PluginSummary, Report, ScanError},
    severity::{Category, Confidence, Severity},
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginManifest {
    pub id: Option<String>,
    pub name: Option<String>,
    pub main: Option<String>,
    pub version: Option<String>,
    pub readme: Option<String>,
    pub icon: Option<String>,
    pub files: Option<Vec<String>>,
    pub min_version_code: Option<u64>,
    pub price: Option<f64>,
    pub changelogs: Option<String>,
}

impl PluginManifest {
    pub fn summary(&self) -> PluginSummary {
        PluginSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            main: self.main.clone(),
            version: self.version.clone(),
            min_version_code: self.min_version_code,
            price: self.price,
        }
    }
}

pub fn load_manifest(archive: &PluginArchive, report: &mut Report) -> Option<PluginManifest> {
    let Some(file) = archive.file("plugin.json") else {
        report.add_finding(
            "manifest.missing",
            Severity::Critical,
            Category::Manifest,
            Some("plugin.json".to_string()),
            None,
            "Plugin archive is missing plugin.json",
            "plugin.json is required for Acode plugins",
            Confidence::High,
        );
        return None;
    };

    match serde_json::from_slice::<PluginManifest>(&file.bytes) {
        Ok(manifest) => Some(manifest),
        Err(error) => {
            report.errors.push(ScanError {
                file: Some("plugin.json".to_string()),
                message: format!("failed to parse plugin.json: {error}"),
            });
            report.add_finding(
                "manifest.invalid_json",
                Severity::Critical,
                Category::Manifest,
                Some("plugin.json".to_string()),
                None,
                "plugin.json is not valid JSON",
                error.to_string(),
                Confidence::High,
            );
            None
        }
    }
}

pub fn validate_manifest(
    manifest: Option<&PluginManifest>,
    archive: &PluginArchive,
    report: &mut Report,
) {
    let Some(manifest) = manifest else {
        return;
    };

    require_string("id", manifest.id.as_deref(), report);
    require_string("name", manifest.name.as_deref(), report);
    require_string("main", manifest.main.as_deref(), report);
    require_string("version", manifest.version.as_deref(), report);

    let mut referenced = Vec::new();
    if let Some(main) = manifest.main.as_deref()
        && (archive.contains(main) || !archive.contains("main.js"))
    {
        referenced.push(("main", main));
    }
    if let Some(readme) = manifest.readme.as_deref() {
        referenced.push(("readme", readme));
    }
    if let Some(icon) = manifest.icon.as_deref() {
        referenced.push(("icon", icon));
    }
    if let Some(changelogs) = manifest.changelogs.as_deref() {
        referenced.push(("changelogs", changelogs));
    }

    for (field, path) in referenced {
        validate_referenced_path(field, path, archive, report);
    }

    if let Some(files) = &manifest.files {
        for path in files {
            validate_referenced_path("files", path, archive, report);
        }
    }

    if let Some(icon) = manifest.icon.as_deref()
        && let Some(file) = archive.file(icon)
        && file.bytes.len() > 50 * 1024
    {
        report.add_finding(
            "manifest.icon_too_large",
            Severity::Low,
            Category::Manifest,
            Some(normalize_zip_path(icon)),
            None,
            "Plugin icon is larger than the documented limit",
            format!(
                "icon size is {} bytes; documented limit is 51200 bytes",
                file.bytes.len()
            ),
            Confidence::High,
        );
    }
}

fn require_string(field: &str, value: Option<&str>, report: &mut Report) {
    if value.is_none_or(|value| value.trim().is_empty()) {
        report.add_finding(
            format!("manifest.missing_{field}"),
            Severity::Critical,
            Category::Manifest,
            Some("plugin.json".to_string()),
            None,
            format!("plugin.json is missing required field `{field}`"),
            "required manifest metadata is absent or empty",
            Confidence::High,
        );
    }
}

fn validate_referenced_path(field: &str, path: &str, archive: &PluginArchive, report: &mut Report) {
    let normalized = normalize_zip_path(path);
    if is_unsafe_path(path) {
        report.add_finding(
            "manifest.unsafe_reference",
            Severity::High,
            Category::Manifest,
            Some("plugin.json".to_string()),
            None,
            format!("Manifest field `{field}` references an unsafe path"),
            path.to_string(),
            Confidence::High,
        );
        return;
    }

    if !archive.contains(&normalized) {
        report.add_finding(
            "manifest.missing_referenced_file",
            Severity::High,
            Category::Manifest,
            Some("plugin.json".to_string()),
            None,
            format!("Manifest field `{field}` references a missing file"),
            normalized,
            Confidence::High,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::PluginArchive;

    fn archive(files: Vec<(&str, &[u8])>) -> PluginArchive {
        PluginArchive {
            files: files
                .into_iter()
                .map(|(name, bytes)| crate::archive::ArchiveFile {
                    name: name.to_string(),
                    bytes: bytes.to_vec(),
                })
                .collect(),
        }
    }

    #[test]
    fn accepts_valid_minimal_manifest() {
        let archive = archive(vec![
            (
                "plugin.json",
                br#"{"id":"x","name":"X","main":"main.js","version":"1"}"#,
            ),
            ("main.js", b""),
        ]);
        let mut report = Report::new("test");
        let manifest = load_manifest(&archive, &mut report);
        validate_manifest(manifest.as_ref(), &archive, &mut report);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn flags_missing_main_file() {
        let archive = archive(vec![(
            "plugin.json",
            br#"{"id":"x","name":"X","main":"main.js","version":"1"}"#,
        )]);
        let mut report = Report::new("test");
        let manifest = load_manifest(&archive, &mut report);
        validate_manifest(manifest.as_ref(), &archive, &mut report);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "manifest.missing_referenced_file")
        );
    }

    #[test]
    fn flags_unsafe_manifest_reference() {
        let archive = archive(vec![(
            "plugin.json",
            br#"{"id":"x","name":"X","main":"../main.js","version":"1"}"#,
        )]);
        let mut report = Report::new("test");
        let manifest = load_manifest(&archive, &mut report);
        validate_manifest(manifest.as_ref(), &archive, &mut report);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "manifest.unsafe_reference")
        );
    }
}
