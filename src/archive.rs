//! Reads a plugin zip the same way Acode installs it.
//!
//! Acode's installer (`src/lib/installPlugin.js`) loads the zip with JSZip and:
//! - keys entries by their raw name; a duplicate name replaces the earlier
//!   entry's content (last one wins),
//! - skips absolute entries (`/x`, `//x`, `C:\x`),
//! - rewrites every other name with `sanitizeZipPath`, which turns `\` into
//!   `/` and *collapses* `..` segments instead of rejecting them, so
//!   `a/../plugin.json` is written over `plugin.json`,
//! - looks up `plugin.json` and `main` by exact raw key,
//! - installs every other entry, including `__MACOSX/` and `.DS_Store` ones
//!   that unzip tools hide.
//!
//! Scanning anything other than what lands on disk lets a plugin show the
//! scanner one file and give users another, so this module keeps both views.

use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{Read, Seek},
    path::Path,
};

use sha2::{Digest, Sha256};
use thiserror::Error;
use zip::{
    CompressionMethod, ZipReadOptions,
    read::Config,
    unstable::read::{ZipIterable, ZipIterableFiles},
};

use crate::{
    report::{FileEntry, Finding, Report},
    severity::{Category, Severity},
};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_entries: usize,
    pub max_entry_bytes: u64,
    pub max_total_bytes: u64,
    /// Uncompressed/compressed ratio above which a large entry looks like a zip bomb.
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 5_000,
            max_entry_bytes: 32 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_ratio: 200,
        }
    }
}

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("failed to open zip archive: {0}")]
    Open(#[from] std::io::Error),
    #[error("not a readable zip archive: {0}")]
    Zip(#[from] zip::result::ZipError),
}

#[derive(Debug, Clone)]
pub struct ArchiveFile {
    /// Name exactly as stored in the zip (the JSZip key).
    pub raw_name: String,
    /// Path the Acode installer writes this entry to.
    pub path: String,
    pub bytes: Vec<u8>,
    /// False when another entry overwrites this one during install.
    pub installed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PluginArchive {
    pub files: Vec<ArchiveFile>,
    /// Raw JSZip key -> index of the entry whose content JSZip keeps.
    by_key: HashMap<String, usize>,
    /// Installed path -> index of the entry that ends up on disk.
    by_path: BTreeMap<String, usize>,
}

impl PluginArchive {
    pub fn read(path: &Path, limits: Limits, report: &mut Report) -> Result<Self, ArchiveError> {
        Self::from_reader(File::open(path)?, limits, report)
    }

    pub fn from_reader<R: Read + Seek>(
        mut reader: R,
        limits: Limits,
        report: &mut Report,
    ) -> Result<Self, ArchiveError> {
        check_header_consistency(&mut reader, limits, report)?;

        // `ZipIterable` walks the central directory in order and keeps
        // duplicate names, like JSZip. (`ZipArchive` indexes entries by name
        // and drops duplicates, which would hide the copy that gets installed.)
        let mut zip = ZipIterable::try_new(&mut reader, Config::default())?;
        let entry_count = zip.len();
        let entries = zip.files()?;
        let mut archive = Self::default();
        let mut total_bytes = 0u64;
        report.stats.archive_entries = entry_count;

        if entry_count > limits.max_entries {
            report.push(
                Finding::new(
                    "archive.too_many_entries",
                    Severity::High,
                    Category::Archive,
                    "Archive has more entries than the scanner will read",
                    format!("{entry_count} entries, limit {}", limits.max_entries),
                )
                .with_file("archive"),
            );
            report.mark_incomplete();
        }

        // Paths written by more than one distinct raw key.
        let mut writers: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for index in 0..entry_count.min(limits.max_entries) {
            let entry = match entries.next() {
                Some(Ok(entry)) => entry,
                Some(Err(error)) => {
                    // The central directory can't be walked past a bad record.
                    report.error(Some("archive"), format!("entry #{index}: {error}"));
                    report.mark_incomplete();
                    break;
                }
                None => break,
            };
            let meta = EntryMeta {
                // JSZip decodes names as UTF-8 whatever the encoding flag says.
                name: String::from_utf8_lossy(entry.name_raw()).into_owned(),
                is_dir: entry.is_dir(),
                encrypted: entry.encrypted(),
                compression: entry.compression(),
                size: entry.size(),
                compressed: entry.compressed_size(),
            };
            let raw = meta.name.clone();

            // No skipping `__MACOSX/` or `.DS_Store` here: the installer writes
            // them like any other entry, so they can carry code.
            if is_unsafe_absolute_path(&raw) {
                report.push(
                    Finding::new(
                        "archive.absolute_path",
                        Severity::Medium,
                        Category::Archive,
                        "Absolute path in archive; Acode skips it on install",
                        raw.clone(),
                    )
                    .with_file(raw.clone()),
                );
                continue;
            }

            if has_traversal_segment(&raw) {
                report.push(
                    Finding::new(
                        "archive.path_traversal",
                        Severity::High,
                        Category::Archive,
                        "Path has `..` segments; Acode collapses them, so this entry can overwrite another file",
                        format!("{raw} -> {}", sanitize_zip_path(&raw)),
                    )
                    .with_file(raw.clone()),
                );
            }

            let is_dir = meta.is_dir || raw.replace('\\', "/").ends_with('/');
            let path = sanitize_zip_path(&raw);
            if is_dir || path.is_empty() {
                continue;
            }

            if meta.encrypted {
                report.push(
                    Finding::new(
                        "archive.encrypted_entry",
                        Severity::High,
                        Category::Archive,
                        "Encrypted entry can't be scanned, and JSZip can't install it",
                        raw.clone(),
                    )
                    .with_file(path.clone()),
                );
                report.mark_incomplete();
                continue;
            }

            if !matches!(
                meta.compression,
                CompressionMethod::Stored | CompressionMethod::Deflated
            ) {
                report.push(
                    Finding::new(
                        "archive.unsupported_compression",
                        Severity::High,
                        Category::Archive,
                        "Entry uses a compression method JSZip can't read, so install will fail",
                        format!("{raw}: {:?}", meta.compression),
                    )
                    .with_file(path.clone()),
                );
                report.mark_incomplete();
                continue;
            }

            if meta.size > limits.max_entry_bytes
                || (meta.size > 1024 * 1024
                    && meta.size / meta.compressed.max(1) > limits.max_ratio)
            {
                report.push(
                    Finding::new(
                        "archive.oversized_entry",
                        Severity::High,
                        Category::Archive,
                        "Entry is too large or too compressible to scan safely (possible zip bomb)",
                        format!(
                            "{raw}: {} bytes uncompressed from {} bytes",
                            meta.size, meta.compressed
                        ),
                    )
                    .with_file(path.clone()),
                );
                report.mark_incomplete();
                continue;
            }

            if total_bytes.saturating_add(meta.size) > limits.max_total_bytes {
                report.push(
                    Finding::new(
                        "archive.total_size_limit",
                        Severity::High,
                        Category::Archive,
                        "Archive expands past the scanner's total size limit",
                        format!("limit {} bytes", limits.max_total_bytes),
                    )
                    .with_file("archive"),
                );
                report.mark_incomplete();
                break;
            }

            // The declared size can lie, so cap the read itself.
            let mut bytes = Vec::with_capacity(meta.size.min(limits.max_entry_bytes) as usize);
            let read = read_entry(entries, entry, limits.max_entry_bytes + 1, &mut bytes);
            if let Err(error) = read {
                report.error(Some(&path), format!("failed to read entry: {error}"));
                report.mark_incomplete();
                continue;
            }
            if bytes.len() as u64 > limits.max_entry_bytes {
                report.push(
                    Finding::new(
                        "archive.oversized_entry",
                        Severity::High,
                        Category::Archive,
                        "Entry expands past its declared size (possible zip bomb)",
                        format!("{raw}: declared {} bytes", meta.size),
                    )
                    .with_file(path.clone()),
                );
                report.mark_incomplete();
                continue;
            }
            total_bytes += bytes.len() as u64;

            let file_index = archive.files.len();
            if let Some(previous) = archive.by_key.insert(raw.clone(), file_index) {
                archive.files[previous].installed = false;
                report.push(
                    Finding::new(
                        "archive.duplicate_entry",
                        Severity::High,
                        Category::Archive,
                        "Same name appears twice; JSZip keeps the last copy, which can differ from what other tools read",
                        raw.clone(),
                    )
                    .with_file(path.clone()),
                );
            }

            let entry_writers = writers.entry(path.clone()).or_default();
            if !entry_writers.contains(&raw) {
                entry_writers.push(raw.clone());
            }
            if let Some(previous) = archive.by_path.insert(path.clone(), file_index) {
                archive.files[previous].installed = false;
            }

            archive.files.push(ArchiveFile {
                raw_name: raw,
                path,
                bytes,
                installed: true,
            });
        }

        for (path, raws) in writers.into_iter().filter(|(_, raws)| raws.len() > 1) {
            report.push(
                Finding::new(
                    "archive.install_path_collision",
                    Severity::Critical,
                    Category::Archive,
                    "Several differently named entries install to the same file; which one wins depends on install order",
                    format!("{path} <- {}", raws.join(", ")),
                )
                .with_file(path),
            );
        }

        archive.flag_suspicious_content(report);
        report.stats.installed_files = archive.by_path.len();
        report.stats.bytes_uncompressed = total_bytes;
        Ok(archive)
    }

    fn flag_suspicious_content(&self, report: &mut Report) {
        for file in self.installed_files() {
            let kind = file_kind(&file.path, &file.bytes);
            if is_os_junk(&file.path) && kind != "metadata" {
                report.push(
                    Finding::new(
                        "archive.metadata_path_content",
                        Severity::Medium,
                        Category::Archive,
                        "File sits in an OS-metadata path that unzip tools and reviewers usually hide, but Acode installs it",
                        format!("{} ({kind})", file.path),
                    )
                    .with_file(file.path.clone())
                    .keyed(&file.path),
                );
            }
            match kind {
                "native_binary" => report.push(
                    Finding::new(
                        "archive.native_binary",
                        Severity::High,
                        Category::Archive,
                        "Native executable or library shipped in the plugin; it can't be reviewed and can be run through Executor",
                        file.path.clone(),
                    )
                    .with_file(file.path.clone())
                    .keyed(&file.path),
                ),
                "archive" => report.push(
                    Finding::new(
                        "archive.nested_archive",
                        Severity::Medium,
                        Category::Archive,
                        "Nested archive is not scanned",
                        file.path.clone(),
                    )
                    .with_file(file.path.clone())
                    .keyed(&file.path),
                ),
                _ => {}
            }
        }
    }

    /// Entry content for a raw JSZip key (what `zip.files[key]` returns).
    pub fn by_key(&self, key: &str) -> Option<&ArchiveFile> {
        self.by_key.get(key).map(|index| &self.files[*index])
    }

    /// File that ends up on disk at an installed path.
    #[cfg(test)]
    pub fn installed(&self, path: &str) -> Option<&ArchiveFile> {
        self.by_path.get(path).map(|index| &self.files[*index])
    }

    pub fn installed_files(&self) -> impl Iterator<Item = &ArchiveFile> {
        self.by_path.values().map(|index| &self.files[*index])
    }

    pub fn file_entries(&self) -> Vec<FileEntry> {
        self.installed_files()
            .map(|file| FileEntry {
                path: file.path.clone(),
                size: file.bytes.len() as u64,
                sha256: sha256_hex(&file.bytes),
                kind: file_kind(&file.path, &file.bytes),
            })
            .collect()
    }

    /// Every distinct piece of JavaScript in the archive, including entries
    /// that get overwritten during install, so nothing hides behind a duplicate.
    pub fn javascript_files(&self) -> Vec<&ArchiveFile> {
        self.distinct_files(&["javascript", "html"])
    }

    /// Every distinct WebAssembly module, found by header or extension.
    pub fn wasm_files(&self) -> Vec<&ArchiveFile> {
        self.distinct_files(&["wasm"])
    }

    fn distinct_files(&self, kinds: &[&str]) -> Vec<&ArchiveFile> {
        let mut seen = std::collections::HashSet::new();
        self.files
            .iter()
            .filter(|file| kinds.contains(&file_kind(&file.path, &file.bytes)))
            .filter(|file| seen.insert((file.path.clone(), sha256_hex(&file.bytes))))
            .collect()
    }
}

/// Reads one entry's content, capped at `limit` bytes.
fn read_entry<R: Read + Seek>(
    entries: &mut ZipIterableFiles<R>,
    entry: zip::read::ZipFileEntry<'static>,
    limit: u64,
    bytes: &mut Vec<u8>,
) -> zip::result::ZipResult<()> {
    let file = entry.with_reader(entries.reader_mut(), ZipReadOptions::new())?;
    file.take(limit).read_to_end(bytes)?;
    Ok(())
}

/// Compares every local file header with its central-directory record.
///
/// Acode (JSZip) and this scanner both trust the central directory, but
/// tools that stream local headers (and some unzip tools reviewers use) do
/// not. When the two disagree on a name, compression, flags, or sizes, the
/// zip shows different files to different readers ("zip cloaking"). This is a
/// separate pass because a failed check stops a pass, and the main read should
/// still see every entry.
fn check_header_consistency<R: Read + Seek>(
    reader: &mut R,
    limits: Limits,
    report: &mut Report,
) -> Result<(), ArchiveError> {
    let mut zip =
        ZipIterable::try_new(&mut *reader, Config::default())?.enforce_header_consistency(true);
    for (index, entry) in zip.files()?.take(limits.max_entries).enumerate() {
        let Err(error) = entry else {
            continue;
        };
        let message = error.to_string();
        if message.contains("header inconsistency") {
            report.push(
                Finding::new(
                    "archive.header_mismatch",
                    Severity::High,
                    Category::Archive,
                    "Local file header disagrees with the central directory, so other zip tools can see different files than Acode installs",
                    format!("entry #{index}: {message}"),
                )
                .with_file("archive"),
            );
        }
        // Other errors stop the main pass too, which reports them.
        break;
    }
    Ok(())
}

struct EntryMeta {
    name: String,
    is_dir: bool,
    encrypted: bool,
    compression: CompressionMethod,
    size: u64,
    compressed: u64,
}

/// Port of `sanitizeZipPath` from Acode's installPlugin.js.
pub fn sanitize_zip_path(raw: &str) -> String {
    let mut path = raw.replace('\\', "/");
    if let Some(index) = path.find("://")
        && index > 0
        && path[..index].chars().all(|ch| ch.is_ascii_alphabetic())
    {
        path = path[index + 3..].to_string();
    }
    let path = path.trim_start_matches('/');
    let path = match path.as_bytes() {
        [drive, b':', b'/', ..] if drive.is_ascii_alphabetic() => &path[3..],
        _ => path,
    };

    let mut stack: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            part => stack.push(part),
        }
    }
    stack.join("/")
}

/// Port of `isUnsafeAbsolutePath` from Acode's installPlugin.js.
pub fn is_unsafe_absolute_path(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    matches!(bytes, [drive, b':', b'\\' | b'/', ..] if drive.is_ascii_alphabetic())
        || raw.starts_with('/')
}

fn has_traversal_segment(raw: &str) -> bool {
    raw.replace('\\', "/").split('/').any(|part| part == "..")
}

fn is_os_junk(raw: &str) -> bool {
    raw.starts_with("__MACOSX/")
        || raw
            .rsplit('/')
            .next()
            .is_some_and(|name| name == ".DS_Store" || name == "Thumbs.db")
}

pub fn extension(path: &str) -> String {
    path.rsplit('/')
        .next()
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default()
}

pub fn file_kind(path: &str, bytes: &[u8]) -> &'static str {
    // AppleDouble (`__MACOSX/._x`), .DS_Store, and Thumbs.db (OLE) headers.
    if bytes.starts_with(&[0x00, 0x05, 0x16, 0x07])
        || bytes.starts_with(b"\x00\x00\x00\x01Bud1")
        || (bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
            && is_os_junk(path))
    {
        return "metadata";
    }
    if bytes.starts_with(crate::wasm::MAGIC) {
        return "wasm";
    }
    if bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"dex\n")
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || (bytes.starts_with(b"MZ") && matches!(extension(path).as_str(), "exe" | "dll"))
    {
        return "native_binary";
    }
    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(&[0x1f, 0x8b])
        || bytes.starts_with(b"7z\xbc\xaf")
        || bytes.starts_with(b"Rar!")
    {
        // Office/font containers are zips too, but plugins rarely ship them.
        return "archive";
    }
    match extension(path).as_str() {
        "js" | "mjs" | "cjs" => "javascript",
        "html" | "htm" => "html",
        "json" => "json",
        "md" | "markdown" | "txt" => "text",
        "css" | "scss" => "style",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "ico" | "bmp" => "image",
        "woff" | "woff2" | "ttf" | "otf" | "eot" => "font",
        "wasm" => "wasm",
        "so" | "dex" | "jar" | "apk" | "aar" => "native_binary",
        "zip" | "tar" | "gz" | "tgz" | "7z" | "rar" | "xz" | "bz2" => "archive",
        _ => "other",
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;

    fn read_zip(files: &[(&str, &[u8])]) -> (PluginArchive, Report) {
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
        (archive, report)
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0u32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// A stored zip written by hand, so tests can build what ZipWriter
    /// refuses to: duplicate names, and local headers that disagree with the
    /// central directory. Entries are (central name, local name, content).
    fn raw_zip(entries: &[(&str, &str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (central_name, local_name, data) in entries {
            let offset = out.len() as u32;
            let (crc, size) = (crc32(data), data.len() as u32);
            out.extend(0x0403_4b50u32.to_le_bytes());
            out.extend([20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            out.extend(crc.to_le_bytes());
            out.extend(size.to_le_bytes());
            out.extend(size.to_le_bytes());
            out.extend((local_name.len() as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes());
            out.extend(local_name.as_bytes());
            out.extend(*data);

            central.extend(0x0201_4b50u32.to_le_bytes());
            central.extend([20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend(crc.to_le_bytes());
            central.extend(size.to_le_bytes());
            central.extend(size.to_le_bytes());
            central.extend((central_name.len() as u16).to_le_bytes());
            central.extend([0u8; 12]);
            central.extend(offset.to_le_bytes());
            central.extend(central_name.as_bytes());
        }
        let (start, length) = (out.len() as u32, central.len() as u32);
        out.extend(central);
        out.extend(0x0605_4b50u32.to_le_bytes());
        out.extend([0u8; 4]);
        out.extend((entries.len() as u16).to_le_bytes());
        out.extend((entries.len() as u16).to_le_bytes());
        out.extend(length.to_le_bytes());
        out.extend(start.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out
    }

    fn read_raw(entries: &[(&str, &str, &[u8])]) -> (PluginArchive, Report) {
        let mut report = Report::new();
        let archive = PluginArchive::from_reader(
            Cursor::new(raw_zip(entries)),
            Limits::default(),
            &mut report,
        )
        .unwrap();
        (archive, report)
    }

    #[test]
    fn keeps_every_copy_of_a_duplicate_name() {
        let (archive, report) = read_raw(&[
            ("main.js", "main.js", b"safe()"),
            ("main.js", "main.js", b"Executor.execute('id')"),
        ]);
        assert!(report.has("archive.duplicate_entry"));
        assert!(!report.has("archive.header_mismatch"));
        // JSZip keeps the last copy, for install and for lookups.
        assert_eq!(
            archive.installed("main.js").unwrap().bytes,
            b"Executor.execute('id')"
        );
        assert_eq!(
            archive.by_key("main.js").unwrap().bytes,
            b"Executor.execute('id')"
        );
        // The overwritten copy is still analysed.
        assert_eq!(archive.javascript_files().len(), 2);
    }

    #[test]
    fn flags_local_headers_that_disagree_with_the_central_directory() {
        let (archive, report) = read_raw(&[
            ("plugin.json", "plugin.json", b"{}"),
            ("main.js", "readme.txt", b"eval(atob(p))"),
        ]);
        assert!(
            report.has("archive.header_mismatch"),
            "{:?}",
            report.findings
        );
        // What Acode installs (central-directory names) is still scanned.
        assert!(archive.installed("main.js").is_some());

        let (_, report) = read_raw(&[("main.js", "main.js", b"x")]);
        assert!(!report.has("archive.header_mismatch"));
    }

    #[test]
    fn sanitizes_like_acode_installer() {
        assert_eq!(sanitize_zip_path("a/../plugin.json"), "plugin.json");
        assert_eq!(sanitize_zip_path("./dist\\main.js"), "dist/main.js");
        assert_eq!(sanitize_zip_path("../../x.js"), "x.js");
        assert_eq!(sanitize_zip_path("C:/x.js"), "x.js");
        assert_eq!(sanitize_zip_path("file://a/b.js"), "a/b.js");
        assert!(is_unsafe_absolute_path("/etc/x"));
        assert!(is_unsafe_absolute_path("C:\\x"));
        assert!(!is_unsafe_absolute_path("a/b"));
    }

    #[test]
    fn traversal_entry_collides_with_real_file() {
        let (archive, report) = read_zip(&[
            ("plugin.json", b"{}"),
            ("x/../plugin.json", b"{\"evil\":1}"),
        ]);
        assert!(report.has("archive.path_traversal"));
        assert!(report.has("archive.install_path_collision"));
        // The later entry is what ends up on disk.
        assert_eq!(
            archive.installed("plugin.json").unwrap().bytes,
            b"{\"evil\":1}"
        );
        // JSZip's exact-key lookup still sees the first one.
        assert_eq!(archive.by_key("plugin.json").unwrap().bytes, b"{}");
    }

    #[test]
    fn skips_absolute_entries_like_installer() {
        let (archive, report) = read_zip(&[("/main.js", b"x")]);
        assert!(report.has("archive.absolute_path"));
        assert!(archive.installed("main.js").is_none());
    }

    #[test]
    fn flags_nested_archives_and_binaries_by_magic() {
        let (_, report) = read_zip(&[
            ("payload.dat", b"PK\x03\x04rest"),
            ("bin/tool", b"\x7fELF\x02\x01"),
        ]);
        assert!(report.has("archive.nested_archive"));
        assert!(report.has("archive.native_binary"));
    }

    #[test]
    fn caps_reads_at_entry_limit() {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            writer
                .start_file("big.js", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&vec![b'a'; 4096]).unwrap();
            writer.finish().unwrap();
        }
        cursor.set_position(0);
        let mut report = Report::new();
        let limits = Limits {
            max_entry_bytes: 1024,
            ..Limits::default()
        };
        let archive = PluginArchive::from_reader(cursor, limits, &mut report).unwrap();
        assert!(report.has("archive.oversized_entry"));
        assert!(!report.verdict.complete);
        assert!(archive.installed("big.js").is_none());
    }

    #[test]
    fn real_macos_metadata_is_quiet() {
        let (archive, report) = read_zip(&[
            (
                "__MACOSX/._main.js",
                b"\x00\x05\x16\x07\x00\x02\x00\x00Mac OS X",
            ),
            ("sub/.DS_Store", b"\x00\x00\x00\x01Bud1\x00\x00"),
            ("main.js", b"y"),
        ]);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        // Acode installs these too, so they are part of the installed tree.
        assert_eq!(archive.installed_files().count(), 3);
        assert_eq!(archive.javascript_files().len(), 1);
    }

    #[test]
    fn code_in_metadata_paths_is_scanned() {
        let (archive, report) = read_zip(&[
            ("__MACOSX/payload.js", b"eval(atob(p))"),
            (".DS_Store", b"Executor.execute('id')"),
            ("main.js", b"y"),
        ]);
        assert!(report.has("archive.metadata_path_content"));
        let scripts: Vec<_> = archive
            .javascript_files()
            .into_iter()
            .map(|file| file.path.as_str())
            .collect();
        assert!(scripts.contains(&"__MACOSX/payload.js"), "{scripts:?}");
    }
}
