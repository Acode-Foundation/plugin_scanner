use std::{
    collections::HashSet,
    fs::File,
    io::{Read, Seek},
    path::Path,
};

use thiserror::Error;
use zip::ZipArchive;

use crate::{
    manifest::PluginManifest,
    report::Report,
    severity::{Category, Confidence, Severity},
};

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;
const NESTED_ARCHIVE_EXTENSIONS: &[&str] = &["zip", "jar", "apk", "aar", "tar", "gz", "7z", "rar"];

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("failed to open zip archive: {0}")]
    Open(#[from] std::io::Error),
    #[error("failed to read zip archive: {0}")]
    Zip(#[from] zip::result::ZipError),
}

#[derive(Debug, Clone)]
pub struct ArchiveFile {
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PluginArchive {
    pub files: Vec<ArchiveFile>,
}

impl PluginArchive {
    pub fn read(path: &Path, report: &mut Report) -> Result<Self, ArchiveError> {
        let file = File::open(path)?;
        Self::from_reader(file, report)
    }

    pub fn from_reader<R: Read + Seek>(
        reader: R,
        report: &mut Report,
    ) -> Result<Self, ArchiveError> {
        let mut archive = ZipArchive::new(reader)?;
        let mut names = HashSet::new();
        let mut files = Vec::new();

        for index in 0..archive.len() {
            let mut entry = archive.by_index(index)?;
            let name = normalize_zip_path(entry.name());

            if name.is_empty() || entry.is_dir() {
                continue;
            }

            if !names.insert(name.clone()) {
                report.add_finding(
                    "archive.duplicate_entry",
                    Severity::Medium,
                    Category::Manifest,
                    Some(name.clone()),
                    None,
                    "Duplicate zip entry",
                    "archive contains the same path more than once",
                    Confidence::High,
                );
            }

            validate_archive_path(&name, report);

            if entry.size() > MAX_FILE_SIZE {
                report.add_finding(
                    "archive.large_file",
                    Severity::Medium,
                    Category::Obfuscation,
                    Some(name.clone()),
                    None,
                    "Large file in plugin archive",
                    format!("file size is {} bytes", entry.size()),
                    Confidence::High,
                );
            }

            if has_nested_archive_extension(&name) {
                report.add_finding(
                    "archive.nested_archive",
                    Severity::Medium,
                    Category::Obfuscation,
                    Some(name.clone()),
                    None,
                    "Nested archive included in plugin",
                    "nested archives are not scanned in v1",
                    Confidence::High,
                );
            }

            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            files.push(ArchiveFile { name, bytes });
        }

        Ok(Self { files })
    }

    pub fn file(&self, name: &str) -> Option<&ArchiveFile> {
        let normalized = normalize_zip_path(name);
        self.files.iter().find(|file| file.name == normalized)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.file(name).is_some()
    }

    pub fn javascript_files(
        &self,
        manifest: Option<&PluginManifest>,
        all_js: bool,
        report: &mut Report,
    ) -> Vec<String> {
        let mut names = Vec::new();
        if all_js {
            for file in &self.files {
                if is_javascript_file(&file.name) {
                    names.push(file.name.clone());
                }
            }
            return names;
        }

        if let Some(entry) = self.resolved_entrypoint(manifest, report) {
            names.push(entry);
        }

        if let Some(files) = manifest.and_then(|manifest| manifest.files.as_ref()) {
            for file in files {
                let normalized = normalize_zip_path(file);
                if is_javascript_file(&normalized)
                    && self.contains(&normalized)
                    && !names.contains(&normalized)
                {
                    names.push(normalized);
                }
            }
        }
        names
    }

    fn resolved_entrypoint(
        &self,
        manifest: Option<&PluginManifest>,
        report: &mut Report,
    ) -> Option<String> {
        if let Some(main) = manifest.and_then(|manifest| manifest.main.as_deref()) {
            let normalized = normalize_zip_path(main);
            if self.contains(&normalized) {
                return Some(normalized);
            }
        }

        if self.contains("main.js") {
            if manifest
                .and_then(|manifest| manifest.main.as_deref())
                .is_some()
            {
                report.add_finding(
                    "manifest.main_fallback",
                    Severity::Low,
                    Category::Manifest,
                    Some("plugin.json".to_string()),
                    None,
                    "Manifest main file is missing; Acode will load main.js fallback",
                    "loadPlugin.js falls back to main.js when pluginJson.main does not exist",
                    Confidence::High,
                );
            }
            return Some("main.js".to_string());
        }

        None
    }
}

fn is_javascript_file(name: &str) -> bool {
    matches!(
        name.rsplit('.')
            .next()
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("js" | "mjs" | "cjs" | "ts")
    )
}

pub fn normalize_zip_path(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches("./").to_string()
}

pub fn is_unsafe_path(path: &str) -> bool {
    let normalized = normalize_zip_path(path);
    normalized.starts_with('/')
        || normalized.starts_with('~')
        || normalized
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

fn validate_archive_path(name: &str, report: &mut Report) {
    if is_unsafe_path(name) {
        report.add_finding(
            "archive.unsafe_path",
            Severity::High,
            Category::Manifest,
            Some(name.to_string()),
            None,
            "Unsafe path in plugin archive",
            "archive path is absolute, empty, or contains traversal segments",
            Confidence::High,
        );
    }
}

fn has_nested_archive_extension(name: &str) -> bool {
    let Some(extension) = name.rsplit('.').next() else {
        return false;
    };
    NESTED_ARCHIVE_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::{ZipWriter, write::FileOptions};

    use super::*;

    fn read_zip(files: &[(&str, &[u8])]) -> Report {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let options: FileOptions<'_, ()> = FileOptions::default();
            for (name, bytes) in files {
                writer.start_file(name, options).unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.set_position(0);
        let mut report = Report::new("test");
        PluginArchive::from_reader(cursor, &mut report).unwrap();
        report
    }

    #[test]
    fn flags_path_traversal() {
        let report = read_zip(&[("../plugin.json", b"{}")]);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "archive.unsafe_path")
        );
    }

    #[test]
    fn flags_nested_archives() {
        let report = read_zip(&[("payload.zip", b"not really a zip")]);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "archive.nested_archive")
        );
    }
}
