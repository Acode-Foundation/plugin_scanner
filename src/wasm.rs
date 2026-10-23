//! WebAssembly modules shipped in, or embedded into, a plugin.
//!
//! A module can only reach the outside world through the functions its JS
//! glue imports into it, and that glue is scanned as JavaScript. What the
//! binary adds is code a reviewer can't read, so this module records what it
//! imports, flags imports that run JavaScript strings, and pulls URLs out of
//! its data segments so hidden hosts still reach the endpoint checks.

use crate::{
    archive::extension,
    report::{Finding, Report},
    rules,
    severity::{Category, Severity},
};

/// `\0asm`, the first four bytes of every WebAssembly binary.
pub const MAGIC: &[u8] = b"\0asm";
/// `\0asm` in base64, how bundlers inline a module into JavaScript.
pub const BASE64_MAGIC: &str = "AGFzbQ";

/// Strings shorter than this in a data segment are not worth checking.
const MIN_STRING_LEN: usize = 8;
const MAX_STRINGS: usize = 20_000;
const MAX_LISTED_IMPORTS: usize = 12;

#[derive(Debug, Default)]
pub struct Module {
    /// `(module, name)` of every imported function, table, memory or global.
    pub imports: Vec<(String, String)>,
    pub exports: Vec<String>,
    /// Printable ASCII runs found in data segments.
    pub strings: Vec<String>,
}

/// Imports whose JavaScript side runs a string from wasm memory as code.
fn is_eval_import(name: &str) -> bool {
    matches!(
        name,
        "emscripten_run_script" | "emscripten_run_script_int" | "emscripten_run_script_string"
    ) || name.starts_with("__wbg_eval_")
}

/// Analyses one module. `embedded` modules came out of a JS string, so their
/// "file name" says nothing about what the bytes are.
pub fn analyze(
    file: &str,
    bytes: &[u8],
    embedded: bool,
    report: &mut Report,
    urls: &mut Vec<(String, String)>,
) {
    let push = |report: &mut Report, id: &str, severity, category, message: &str, evidence| {
        report.push(
            Finding::new(id, severity, category, message, evidence)
                .with_file(file)
                .keyed(file),
        );
    };

    if !bytes.starts_with(MAGIC) {
        push(
            report,
            "wasm.bad_magic",
            Severity::Medium,
            Category::Wasm,
            "File is named .wasm but isn't WebAssembly",
            format!("starts with {:02x?}", &bytes[..bytes.len().min(8)]),
        );
        return;
    }
    if !embedded && extension(file) != "wasm" {
        push(
            report,
            "wasm.disguised",
            Severity::Medium,
            Category::Wasm,
            "WebAssembly binary hidden under another file extension",
            file.to_string(),
        );
    }

    let module = match parse(bytes) {
        Ok(module) => module,
        Err(error) => {
            push(
                report,
                "wasm.parse_failed",
                Severity::Medium,
                Category::Wasm,
                "WebAssembly module could not be parsed, so its imports and data weren't checked",
                error,
            );
            report.mark_incomplete();
            return;
        }
    };

    let mut listed: Vec<String> = module
        .imports
        .iter()
        .take(MAX_LISTED_IMPORTS)
        .map(|(module, name)| format!("{module}.{name}"))
        .collect();
    if module.imports.len() > MAX_LISTED_IMPORTS {
        listed.push(format!(
            "… {} more",
            module.imports.len() - MAX_LISTED_IMPORTS
        ));
    }
    push(
        report,
        "wasm.module",
        Severity::Low,
        Category::Wasm,
        "Ships compiled WebAssembly, which can't be reviewed as source",
        format!(
            "{} bytes, {} imports, {} exports; imports: {}",
            bytes.len(),
            module.imports.len(),
            module.exports.len(),
            if listed.is_empty() {
                "none".to_string()
            } else {
                listed.join(", ")
            }
        ),
    );

    for (import_module, name) in &module.imports {
        if is_eval_import(name) {
            report.push(
                Finding::new(
                    "wasm.eval_import",
                    Severity::High,
                    Category::DynamicCode,
                    "WebAssembly module can run JavaScript strings built inside the binary",
                    format!("{import_module}.{name}"),
                )
                .with_file(file)
                // The hash suffix of wasm-bindgen names changes every build.
                .keyed(name.trim_end_matches(|ch: char| ch.is_ascii_hexdigit())),
            );
        }
    }

    for string in &module.strings {
        if string.contains("://") {
            urls.extend(
                rules::extract_urls(string)
                    .into_iter()
                    .map(|url| (file.to_string(), url)),
            );
        }
    }
}

pub fn parse(bytes: &[u8]) -> Result<Module, String> {
    let mut reader = Reader::new(bytes);
    if reader.take(4)? != MAGIC {
        return Err("missing \\0asm header".into());
    }
    let version = reader.take(4)?;
    if version != [1, 0, 0, 0] {
        return Err(format!("unsupported version {version:02x?}"));
    }

    let mut module = Module::default();
    while !reader.done() {
        let id = reader.byte()?;
        let size = reader.uleb()? as usize;
        let payload = reader.take(size)?;
        let mut section = Reader::new(payload);
        match id {
            2 => read_imports(&mut section, &mut module)
                .map_err(|e| format!("import section: {e}"))?,
            7 => read_exports(&mut section, &mut module)
                .map_err(|e| format!("export section: {e}"))?,
            11 => read_data(&mut section, &mut module).map_err(|e| format!("data section: {e}"))?,
            _ => {}
        }
    }
    Ok(module)
}

fn read_imports(reader: &mut Reader<'_>, module: &mut Module) -> Result<(), String> {
    for _ in 0..reader.uleb()? {
        let import_module = reader.name()?;
        let name = reader.name()?;
        match reader.byte()? {
            // function: type index
            0x00 => {
                reader.uleb()?;
            }
            // table: reference type + limits
            0x01 => {
                reader.byte()?;
                reader.limits()?;
            }
            // memory: limits
            0x02 => reader.limits()?,
            // global: value type + mutability
            0x03 => {
                reader.byte()?;
                reader.byte()?;
            }
            // tag: attribute + type index
            0x04 => {
                reader.byte()?;
                reader.uleb()?;
            }
            kind => return Err(format!("unknown import kind {kind:#x}")),
        }
        module.imports.push((import_module, name));
    }
    Ok(())
}

fn read_exports(reader: &mut Reader<'_>, module: &mut Module) -> Result<(), String> {
    for _ in 0..reader.uleb()? {
        let name = reader.name()?;
        reader.byte()?;
        reader.uleb()?;
        module.exports.push(name);
    }
    Ok(())
}

fn read_data(reader: &mut Reader<'_>, module: &mut Module) -> Result<(), String> {
    for _ in 0..reader.uleb()? {
        match reader.uleb()? {
            0 => reader.const_expr()?,
            1 => {}
            2 => {
                reader.uleb()?;
                reader.const_expr()?;
            }
            flag => return Err(format!("unknown data segment flag {flag}")),
        }
        let len = reader.uleb()? as usize;
        let data = reader.take(len)?;
        collect_strings(data, &mut module.strings);
    }
    Ok(())
}

fn collect_strings(data: &[u8], out: &mut Vec<String>) {
    for run in data.split(|byte| !(0x20..0x7f).contains(byte) && *byte != b'\t') {
        if out.len() >= MAX_STRINGS {
            return;
        }
        if run.len() >= MIN_STRING_LEN {
            out.push(String::from_utf8_lossy(run).into_owned());
        }
    }
}

/// Bounds-checked reader for the binary format. Every read fails instead of
/// panicking, so a hostile module can only make the parse fail.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn byte(&mut self) -> Result<u8, String> {
        let byte = *self.bytes.get(self.pos).ok_or("unexpected end")?;
        self.pos += 1;
        Ok(byte)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(len).ok_or("length overflow")?;
        let slice = self.bytes.get(self.pos..end).ok_or("unexpected end")?;
        self.pos = end;
        Ok(slice)
    }

    fn uleb(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("LEB128 too long".into())
    }

    /// Signed LEB128; only its length matters here.
    fn skip_sleb(&mut self) -> Result<(), String> {
        for _ in 0..10 {
            if self.byte()? & 0x80 == 0 {
                return Ok(());
            }
        }
        Err("LEB128 too long".into())
    }

    fn name(&mut self) -> Result<String, String> {
        let len = self.uleb()? as usize;
        Ok(String::from_utf8_lossy(self.take(len)?).into_owned())
    }

    fn limits(&mut self) -> Result<(), String> {
        let flags = self.byte()?;
        self.uleb()?;
        if flags & 0x01 != 0 {
            self.uleb()?;
        }
        Ok(())
    }

    /// Constant expression ending in `end`, as used for data segment offsets.
    fn const_expr(&mut self) -> Result<(), String> {
        loop {
            match self.byte()? {
                0x0b => return Ok(()),
                0x41 | 0x42 => self.skip_sleb()?,
                0x23 => {
                    self.uleb()?;
                }
                0x43 => {
                    self.take(4)?;
                }
                0x44 => {
                    self.take(8)?;
                }
                // Extended constant arithmetic (i32/i64 add, sub, mul).
                0x6a..=0x6c | 0x7c..=0x7e => {}
                opcode => return Err(format!("unsupported opcode {opcode:#x} in offset")),
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    fn uleb(mut value: usize, out: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn name(text: &str, out: &mut Vec<u8>) {
        uleb(text.len(), out);
        out.extend_from_slice(text.as_bytes());
    }

    fn section(id: u8, payload: Vec<u8>, out: &mut Vec<u8>) {
        out.push(id);
        uleb(payload.len(), out);
        out.extend(payload);
    }

    /// Minimal module importing functions `(module, name)` and holding `data`
    /// in one active data segment.
    pub fn module(imports: &[(&str, &str)], data: &[u8]) -> Vec<u8> {
        let mut out = b"\0asm\x01\0\0\0".to_vec();
        // One `() -> ()` function type.
        section(1, vec![1, 0x60, 0, 0], &mut out);
        let mut payload = Vec::new();
        uleb(imports.len(), &mut payload);
        for (module, field) in imports {
            name(module, &mut payload);
            name(field, &mut payload);
            payload.extend([0x00, 0x00]);
        }
        section(2, payload, &mut out);
        // memory 1 page
        section(5, vec![1, 0, 1], &mut out);
        let mut payload = vec![1, 0, 0x41, 0, 0x0b];
        uleb(data.len(), &mut payload);
        payload.extend_from_slice(data);
        section(11, payload, &mut out);
        out
    }

    #[test]
    fn reads_imports_and_data_strings() {
        let bytes = module(
            &[("env", "emscripten_run_script"), ("wbg", "__wbg_log_1a2b")],
            b"\0\0https://webhook.site/abc\0short\0",
        );
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.imports.len(), 2);
        assert_eq!(parsed.imports[0].1, "emscripten_run_script");
        assert!(parsed.strings.iter().any(|s| s.contains("webhook.site")));
        assert!(!parsed.strings.iter().any(|s| s == "short"));
    }

    #[test]
    fn truncated_modules_fail_cleanly() {
        let bytes = module(&[("env", "f")], b"data");
        for len in 8..bytes.len() {
            let _ = parse(&bytes[..len]);
        }
        assert!(parse(&bytes[..bytes.len() - 1]).is_err());
        assert!(parse(b"\0asm\x02\0\0\0").is_err());
    }

    #[test]
    fn flags_eval_imports_and_disguised_modules() {
        let mut report = Report::new();
        let mut urls = Vec::new();
        let bytes = module(&[("wbg", "__wbg_eval_9f3c2a")], b"");
        analyze("assets/font.dat", &bytes, false, &mut report, &mut urls);
        assert!(report.has("wasm.eval_import"));
        assert!(report.has("wasm.disguised"));
        assert!(report.has("wasm.module"));

        let mut report = Report::new();
        analyze("lib.wasm", b"console.log(1)", false, &mut report, &mut urls);
        assert!(report.has("wasm.bad_magic"));
    }
}
