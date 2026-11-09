//! Grades a shell command by what it actually runs.
//!
//! Every terminal plugin calls `Executor`, so "runs a shell command" alone
//! says little. This module splits a command into its simple commands (on
//! `;`, `&&`, `||`, `|`, `&`, newlines, subshells, and `$(…)`) and grades each:
//!
//! - **Inspect** (Low): read-only commands such as `uname -m`, `cat`,
//!   `command -v x`, `ls`, `test -f`, or `tool --version`.
//! - **Program** (Medium): visible commands with side effects, such as
//!   installing packages, moving files, or starting a local server.
//! - **Opaque** (High): the scanner cannot see what runs: the command name is
//!   built at runtime, `sh -c` / `eval` / `node -e` get a runtime string, or
//!   text is piped into a shell or interpreter.
//!
//! Known-bad patterns (download-and-run, reverse shells, wiping storage...)
//! are matched separately by the command rules in `rules.rs`.

use std::collections::HashMap;

use crate::severity::Severity;

/// What the JS resolver puts in place of a value it cannot work out.
pub const HOLE: char = '…';

const MAX_DEPTH: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Inspect,
    Program,
    Opaque,
}

impl Tier {
    pub fn severity(self) -> Severity {
        match self {
            Self::Inspect => Severity::Low,
            Self::Program => Severity::Medium,
            Self::Opaque => Severity::High,
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Program => "program",
            Self::Opaque => "opaque",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub tier: Tier,
    /// Why the command got its tier (the first reason at the highest tier).
    pub reason: String,
    /// Starts an interactive shell, so text later written to the process is
    /// a command too.
    pub opens_shell: bool,
}

impl Assessment {
    pub fn opaque(reason: impl Into<String>) -> Self {
        Self {
            tier: Tier::Opaque,
            reason: reason.into(),
            opens_shell: false,
        }
    }

    fn inspect() -> Self {
        Self {
            tier: Tier::Inspect,
            reason: "read-only commands".to_string(),
            opens_shell: false,
        }
    }

    fn program(reason: impl Into<String>) -> Self {
        Self {
            tier: Tier::Program,
            reason: reason.into(),
            opens_shell: false,
        }
    }

    fn merge(&mut self, other: Self) {
        let opens_shell = self.opens_shell || other.opens_shell;
        if other.tier > self.tier {
            *self = other;
        }
        self.opens_shell = opens_shell;
    }
}

pub fn assess(command: &str) -> Assessment {
    let mut result = assess_at(command, 0);
    // A runtime value can carry anything (`echo ${x}` with `x = "; curl …"`),
    // so only a command the scanner can read in full counts as read-only.
    if command.contains(HOLE) {
        result.merge(Assessment::program("includes values built at runtime"));
    }
    result
}

fn assess_at(command: &str, depth: u8) -> Assessment {
    if depth > MAX_DEPTH {
        return Assessment::opaque("commands nested too deeply to follow");
    }
    let mut substitutions = Vec::new();
    let segments = split(command, &mut substitutions);
    let mut result = Assessment::inspect();
    // Variables assigned earlier in the same script: `P=/x/proot; $P ...`.
    let mut vars = HashMap::new();
    for segment in &segments {
        result.merge(assess_segment(segment, depth, &mut vars));
    }
    for inner in substitutions {
        result.merge(assess_at(&inner, depth + 1));
    }
    result
}

/// One simple command: its words with quotes removed and redirections
/// dropped, and whether its stdin is piped from the previous command.
#[derive(Debug, Default)]
struct Segment {
    words: Vec<String>,
    piped: bool,
}

struct Splitter {
    segments: Vec<Segment>,
    words: Vec<String>,
    word: String,
    in_word: bool,
    /// The next word is a redirection target (`> file`).
    drop_next_word: bool,
    piped: bool,
}

impl Splitter {
    fn flush_word(&mut self) {
        if self.in_word {
            let word = std::mem::take(&mut self.word);
            if self.drop_next_word {
                self.drop_next_word = false;
            } else {
                self.words.push(word);
            }
        }
        self.in_word = false;
    }

    /// Ends the current simple command. `next_piped` is whether the next one
    /// reads this one's output; `None` keeps the current state (subshells).
    fn flush_segment(&mut self, next_piped: Option<bool>) {
        self.flush_word();
        self.drop_next_word = false;
        if !self.words.is_empty() {
            self.segments.push(Segment {
                words: std::mem::take(&mut self.words),
                piped: self.piped,
            });
            self.piped = false;
        }
        if let Some(piped) = next_piped {
            self.piped = piped;
        }
    }

    fn push(&mut self, ch: char) {
        self.word.push(ch);
        self.in_word = true;
    }
}

/// Index just past the `)` that closes a `(` opened right before `start`.
fn balanced_end(chars: &[char], start: usize) -> usize {
    let mut depth = 1;
    let mut index = start;
    let mut quote: Option<char> = None;
    while index < chars.len() {
        let ch = chars[index];
        match quote {
            Some(q) if ch == q => quote = None,
            Some('"') if ch == '\\' => index += 1,
            Some(_) => {}
            None => match ch {
                '\'' | '"' => quote = Some(ch),
                '\\' => index += 1,
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return index + 1;
                    }
                }
                _ => {}
            },
        }
        index += 1;
    }
    chars.len()
}

fn split(command: &str, substitutions: &mut Vec<String>) -> Vec<Segment> {
    let chars: Vec<char> = command.chars().collect();
    let mut s = Splitter {
        segments: Vec::new(),
        words: Vec::new(),
        word: String::new(),
        in_word: false,
        drop_next_word: false,
        piped: false,
    };
    let mut in_double = false;
    let mut index = 0;
    let at = |i: usize| chars.get(i).copied();

    while index < chars.len() {
        let ch = chars[index];

        // Command substitution works inside double quotes too.
        if (ch == '$' && at(index + 1) == Some('(') && at(index + 2) != Some('('))
            || ch == '`'
            || (!in_double && matches!(ch, '<' | '>') && at(index + 1) == Some('('))
        {
            let (inner, end) = if ch == '`' {
                let end = chars[index + 1..]
                    .iter()
                    .position(|c| *c == '`')
                    .map_or(chars.len(), |offset| index + 1 + offset);
                (chars[index + 1..end].iter().collect(), end + 1)
            } else {
                let end = balanced_end(&chars, index + 2);
                let close = end.saturating_sub(1).max(index + 2);
                (
                    chars[index + 2..close.min(chars.len())].iter().collect(),
                    end,
                )
            };
            substitutions.push(inner);
            s.word.push_str("$(…)");
            s.in_word = true;
            index = end;
            continue;
        }

        if in_double {
            match ch {
                '"' => in_double = false,
                '\\' if matches!(at(index + 1), Some('"' | '\\' | '$' | '`')) => {
                    s.push(chars[index + 1]);
                    index += 1;
                }
                _ => s.push(ch),
            }
            index += 1;
            continue;
        }

        match ch {
            '\'' => {
                let end = chars[index + 1..]
                    .iter()
                    .position(|c| *c == '\'')
                    .map_or(chars.len(), |offset| index + 1 + offset);
                s.word.extend(&chars[index + 1..end]);
                s.in_word = true;
                index = end;
            }
            '"' => {
                in_double = true;
                s.in_word = true;
            }
            '\\' => {
                if let Some(next) = at(index + 1) {
                    if next != '\n' {
                        s.push(next);
                    }
                    index += 1;
                }
            }
            '#' if !s.in_word => {
                while index < chars.len() && chars[index] != '\n' {
                    index += 1;
                }
                continue;
            }
            ' ' | '\t' | '\r' => s.flush_word(),
            '\n' | ';' => s.flush_segment(Some(false)),
            '&' if at(index + 1) == Some('&') => {
                s.flush_segment(Some(false));
                index += 1;
            }
            '&' if at(index + 1) == Some('>') => {
                s.flush_word();
                index += 1;
                if at(index + 1) == Some('>') {
                    index += 1;
                }
                s.drop_next_word = true;
            }
            '&' => s.flush_segment(Some(false)),
            '|' if at(index + 1) == Some('|') => {
                s.flush_segment(Some(false));
                index += 1;
            }
            '|' => {
                s.flush_segment(Some(true));
                if at(index + 1) == Some('&') {
                    index += 1;
                }
            }
            '(' | ')' => s.flush_segment(None),
            '>' | '<' => {
                // `2>&1`: the digits are a file descriptor, not a word.
                if s.in_word && s.word.chars().all(|c| c.is_ascii_digit()) {
                    s.word.clear();
                    s.in_word = false;
                } else {
                    s.flush_word();
                }
                while matches!(at(index + 1), Some('>' | '<' | '&' | '|')) {
                    index += 1;
                }
                s.drop_next_word = true;
            }
            _ => s.push(ch),
        }
        index += 1;
    }
    s.flush_segment(None);
    s.segments
}

fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Drops leading `-x` options; `with_value` options also drop the next word.
fn skip_options<'w>(mut words: &'w [String], with_value: &[&str]) -> &'w [String] {
    while let Some(first) = words.first() {
        if first == "--" {
            return &words[1..];
        }
        if !first.starts_with('-') || first == "-" {
            break;
        }
        let takes_value = with_value.contains(&first.as_str());
        words = &words[if takes_value { 2 } else { 1 }.min(words.len())..];
    }
    words
}

fn is_info_flag(word: &str) -> bool {
    matches!(
        word,
        "--version" | "-v" | "-V" | "version" | "--help" | "-h" | "help"
    )
}

/// Commands that only read or report state.
const INSPECT: &[&str] = &[
    "echo",
    "printf",
    "true",
    "false",
    "test",
    "[",
    "[[",
    "]]",
    ":",
    "pwd",
    "ls",
    "cat",
    "tac",
    "head",
    "tail",
    "wc",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "stat",
    "file",
    "date",
    "sleep",
    "ps",
    "pgrep",
    "pidof",
    "df",
    "du",
    "free",
    "uptime",
    "uname",
    "whoami",
    "id",
    "groups",
    "hostname",
    "nproc",
    "arch",
    "getprop",
    "getconf",
    "which",
    "whereis",
    "type",
    "basename",
    "dirname",
    "readlink",
    "realpath",
    "printenv",
    "cut",
    "sort",
    "uniq",
    "tr",
    "seq",
    "expr",
    "jq",
    "nl",
    "od",
    "xxd",
    "hexdump",
    "strings",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "cmp",
    "diff",
    "column",
    "fold",
    "paste",
    "comm",
    "lscpu",
    "locale",
    "tty",
    "who",
    "logname",
    "cd",
    "export",
    "unset",
    "set",
    "read",
    "return",
    "exit",
    "wait",
    "shift",
    "local",
    "declare",
    "typeset",
    "hash",
    "clear",
    "reset",
    "break",
    "continue",
];

/// Shell grammar words that wrap a command rather than being one.
const PREFIX_WORDS: &[&str] = &[
    "!", "{", "}", "if", "then", "else", "elif", "do", "while", "until", "time", "nohup", "setsid",
    "exec", "builtin", "stdbuf", "unbuffer",
];

/// Shell grammar words that start or end a block and run nothing themselves.
const BLOCK_WORDS: &[&str] = &[
    "fi", "done", "esac", "for", "case", "select", "in", "function",
];

const SHELLS: &[&str] = &["sh", "bash", "ash", "zsh", "dash", "ksh", "mksh", "fish"];

/// Interpreters and the options that take inline code.
const INTERPRETERS: &[(&str, &str, &[&str])] = &[
    ("node", "JavaScript", &["-e", "--eval", "-p", "--print"]),
    ("nodejs", "JavaScript", &["-e", "--eval", "-p", "--print"]),
    ("bun", "JavaScript", &["-e", "--eval", "-p", "--print"]),
    ("deno", "JavaScript", &["eval"]),
    ("python", "Python", &["-c"]),
    ("python2", "Python", &["-c"]),
    ("python3", "Python", &["-c"]),
    ("perl", "Perl", &["-e", "-E"]),
    ("ruby", "Ruby", &["-e"]),
    ("php", "PHP", &["-r"]),
    ("lua", "Lua", &["-e"]),
    ("luajit", "Lua", &["-e"]),
];

/// Read-only subcommands of package managers and git.
fn is_query_subcommand(program: &str, args: &[String]) -> bool {
    let first = args.first().map(String::as_str).unwrap_or_default();
    match program {
        "npm" | "pnpm" | "yarn" => matches!(
            first,
            "root" | "prefix" | "bin" | "ls" | "list" | "view" | "info" | "outdated" | "-v"
        ),
        "apk" => matches!(first, "info" | "list" | "search" | "policy" | "version"),
        "apt" | "apt-cache" | "dpkg" => {
            matches!(first, "list" | "search" | "show" | "policy" | "-l" | "-s")
        }
        "pip" | "pip3" => matches!(first, "show" | "list" | "freeze"),
        "git" => matches!(
            first,
            "status" | "log" | "rev-parse" | "describe" | "diff" | "show" | "branch"
        ),
        _ => false,
    }
}

fn program_reason(program: &str) -> String {
    let what = match program {
        "apk" | "apt" | "apt-get" | "dpkg" | "pkg" | "pacman" | "dnf" | "yum" | "zypper"
        | "npm" | "npx" | "pnpm" | "pnpx" | "yarn" | "pip" | "pip3" | "pipx" | "gem" | "cargo"
        | "go" | "composer" => "installs or manages packages",
        "curl" | "wget" | "nc" | "ncat" | "socat" | "ssh" | "scp" | "sftp" | "rsync" | "ftp"
        | "telnet" | "git" => "uses the network",
        "mkdir" | "cp" | "mv" | "ln" | "touch" | "chmod" | "chown" | "chgrp" | "rm" | "rmdir"
        | "tar" | "unzip" | "zip" | "gzip" | "gunzip" | "xz" | "unxz" | "bzip2" | "7z"
        | "install" | "truncate" | "dd" | "tee" | "mktemp" | "shred" | "mkfifo" | "sed"
        | "find" => "changes files",
        "kill" | "pkill" | "killall" | "trap" => "controls processes",
        "proot" | "chroot" | "unshare" | "mount" => "runs a container or changes mounts",
        _ => return format!("runs `{program}`"),
    };
    format!("{what} (`{program}`)")
}

fn record_assignment(vars: &mut HashMap<String, String>, word: &str) {
    if let Some((name, value)) = word.split_once('=')
        && is_assignment(word)
    {
        vars.insert(name.to_string(), value.to_string());
    }
}

/// `NAME` for a word that is exactly `$NAME` or `${NAME}`.
fn shell_var(word: &str) -> Option<&str> {
    let rest = word.strip_prefix('$')?;
    let name = rest
        .strip_prefix('{')
        .and_then(|inner| inner.strip_suffix('}'))
        .unwrap_or(rest);
    let mut chars = name.chars();
    (chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_'))
    .then_some(name)
}

fn assess_segment(segment: &Segment, depth: u8, vars: &mut HashMap<String, String>) -> Assessment {
    let mut words = segment.words.as_slice();
    let mut floor = Assessment::inspect();

    // Strip assignments and wrappers until the real command name.
    loop {
        let Some(first) = words.first() else {
            return floor;
        };
        let name = first.as_str();
        if is_assignment(name) {
            record_assignment(vars, name);
            words = &words[1..];
        } else if PREFIX_WORDS.contains(&name) {
            words = &words[1..];
        } else if BLOCK_WORDS.contains(&name) {
            return floor;
        } else if matches!(name, "sudo" | "doas") {
            floor.merge(Assessment::program("runs commands as root"));
            words = skip_options(&words[1..], &["-u", "-g", "-C"]);
        } else if matches!(name, "nice" | "ionice") {
            words = skip_options(&words[1..], &["-n", "-c"]);
        } else if name == "timeout" {
            words = skip_options(&words[1..], &["-s", "-k"]);
            words = words.get(1..).unwrap_or_default();
        } else if name == "env" {
            words = skip_options(&words[1..], &["-u", "-C", "-S"]);
            while words.first().is_some_and(|word| is_assignment(word)) {
                words = &words[1..];
            }
        } else if name == "command" {
            if words
                .get(1)
                .is_some_and(|word| matches!(word.as_str(), "-v" | "-V"))
            {
                return floor;
            }
            words = skip_options(&words[1..], &[]);
        } else if name == "busybox" || name == "toybox" {
            words = &words[1..];
        } else if name == "xargs" {
            words = skip_options(
                &words[1..],
                &["-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a"],
            );
        } else {
            break;
        }
    }

    let mut name = words[0].as_str();
    let args = &words[1..];
    let assigned;
    if let Some(value) = shell_var(name).and_then(|var| vars.get(var)) {
        assigned = value
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        name = &assigned;
    }
    if name.contains(HOLE) {
        return Assessment::opaque("the command name is built at runtime");
    }
    let program = name.rsplit('/').next().unwrap_or(name);
    // `$PREFIX/bin/tool` is still `tool`; only a name that is itself a
    // variable is unknown.
    if program.is_empty() || program.contains('$') {
        return Assessment::opaque("the command name comes from a shell variable or substitution");
    }
    let program = program.strip_suffix(".exe").unwrap_or(program);

    if matches!(
        program,
        "export" | "local" | "declare" | "readonly" | "typeset"
    ) {
        for arg in args {
            record_assignment(vars, arg);
        }
        return floor;
    }
    if program == "chroot" || program.contains("proot") {
        let rest = if program == "chroot" {
            let rest = skip_options(args, &["--userspec", "--groups"]);
            rest.get(1..).unwrap_or_default()
        } else {
            let mut rest = args;
            loop {
                let skipped = skip_options(
                    rest,
                    &[
                        "-r",
                        "-b",
                        "-m",
                        "-w",
                        "-q",
                        "-k",
                        "-R",
                        "-S",
                        "-p",
                        "--bind",
                        "--rootfs",
                        "--cwd",
                        "--mount",
                        "--kernel-release",
                    ],
                );
                // `$ARGS` holding the options.
                let skipped = match skipped.first() {
                    Some(word) if word.starts_with('$') && !word.contains('/') => &skipped[1..],
                    _ => skipped,
                };
                if skipped.len() == rest.len() {
                    break rest;
                }
                rest = skipped;
            }
        };
        floor.merge(Assessment::program(format!(
            "runs a container (`{program}`)"
        )));
        if rest.is_empty() {
            floor.merge(Assessment {
                opens_shell: true,
                ..Assessment::program("starts a shell in a container")
            });
        } else {
            let inner = Segment {
                words: rest.to_vec(),
                piped: segment.piped,
            };
            floor.merge(assess_segment(&inner, depth + 1, vars));
        }
        return floor;
    }

    if SHELLS.contains(&program) {
        floor.merge(assess_shell(args, segment.piped, depth));
        return floor;
    }
    if program == "eval" {
        let script = args.join(" ");
        floor.merge(if script.trim() == HOLE.to_string() {
            Assessment::opaque("`eval` runs text built at runtime")
        } else {
            assess_at(&script, depth + 1)
        });
        return floor;
    }
    if program == "source" || program == "." {
        floor.merge(Assessment::program("sources a shell script file"));
        return floor;
    }
    if let Some((_, language, inline)) = INTERPRETERS.iter().find(|(name, ..)| *name == program) {
        floor.merge(assess_interpreter(
            program,
            language,
            inline,
            args,
            segment.piped,
        ));
        return floor;
    }
    if !args.is_empty() && args.iter().all(|arg| is_info_flag(arg)) {
        return floor;
    }
    if is_query_subcommand(program, args) {
        return floor;
    }
    let read_only = match program {
        "find" => !args.iter().any(|arg| {
            matches!(
                arg.as_str(),
                "-exec" | "-execdir" | "-ok" | "-okdir" | "-delete" | "-fprint" | "-fls"
            )
        }),
        "sed" => !args
            .iter()
            .any(|arg| arg.starts_with("-i") || arg == "--in-place"),
        "awk" | "gawk" | "mawk" => !args
            .iter()
            .any(|arg| arg.contains("system") || arg.contains("getline") || arg.contains('>')),
        _ => INSPECT.contains(&program),
    };
    if !read_only {
        floor.merge(Assessment::program(program_reason(program)));
    }
    floor
}

fn assess_shell(args: &[String], piped: bool, depth: u8) -> Assessment {
    let mut inline = false;
    let mut rest = args;
    while let Some(first) = rest.first() {
        if first.starts_with('-') && !first.starts_with("--") && first.len() > 1 {
            inline |= first.contains('c');
            rest = &rest[1..];
        } else if first.starts_with("--") {
            rest = &rest[1..];
        } else {
            break;
        }
    }
    match rest.first() {
        // Runtime parts inside the script are graded where they appear: a
        // runtime path is fine, a runtime command name is not.
        Some(script) if inline => {
            if script.trim() == HOLE.to_string() {
                Assessment::opaque("`sh -c` runs a script built at runtime")
            } else {
                assess_at(script, depth + 1)
            }
        }
        Some(_) => Assessment::program("runs a shell script file"),
        None if piped => Assessment::opaque("pipes text into a shell"),
        None => Assessment {
            opens_shell: true,
            ..Assessment::program("starts an interactive shell")
        },
    }
}

fn assess_interpreter(
    program: &str,
    language: &str,
    inline: &[&str],
    args: &[String],
    piped: bool,
) -> Assessment {
    let code = args
        .iter()
        .position(|arg| inline.contains(&arg.as_str()))
        .map(|index| args.get(index + 1).map(String::as_str).unwrap_or_default());
    match code {
        Some(code) if code.contains(HOLE) => {
            Assessment::opaque(format!("runs inline {language} code built at runtime"))
        }
        Some(_) => Assessment::program(format!("runs inline {language} code")),
        None if args.is_empty() && piped => {
            Assessment::opaque(format!("pipes text into `{program}`"))
        }
        None if !args.is_empty() && args.iter().all(|arg| is_info_flag(arg)) => {
            Assessment::inspect()
        }
        None => Assessment::program(format!("runs `{program}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(command: &str) -> Tier {
        assess(command).tier
    }

    fn words(command: &str) -> Vec<Vec<String>> {
        split(command, &mut Vec::new())
            .into_iter()
            .map(|segment| segment.words)
            .collect()
    }

    #[test]
    fn splits_commands_like_a_shell() {
        assert_eq!(
            words("cd \"$HOME\" 2>/dev/null || cd /; echo 'a b' > /tmp/x"),
            vec![
                vec!["cd".to_string(), "$HOME".into()],
                vec!["cd".into(), "/".into()],
                vec!["echo".into(), "a b".into()],
            ]
        );
        assert_eq!(
            words("tar -xf a.tar 2>&1 | tail -n 1 &"),
            vec![
                vec!["tar".to_string(), "-xf".into(), "a.tar".into()],
                vec!["tail".into(), "-n".into(), "1".into()],
            ]
        );
        let mut substitutions = Vec::new();
        split("X=\"$(uname -m)\" && echo `id -u`", &mut substitutions);
        assert_eq!(substitutions, vec!["uname -m".to_string(), "id -u".into()]);
    }

    #[test]
    fn read_only_commands_are_inspect() {
        for command in [
            "uname -m",
            "command -v opencode && echo yes",
            "opencode --version 2>&1 && echo OCOK",
            "tail -n 15 /tmp/opencode.log",
            "npm root -g",
            "[ -d ~/.config ] && echo ok",
            "node -v",
            "",
        ] {
            assert_eq!(tier(command), Tier::Inspect, "{command}");
        }
    }

    #[test]
    fn visible_side_effects_are_program() {
        for command in [
            "apk add --no-cache nodejs npm git 2>&1",
            "npm install -g opencode-linux-…-musl 2>&1",
            "B=…/bin/opencode; [ -f \"$B\" ] && ln -sf \"$B\" /usr/local/bin/opencode; echo done",
            "cd \"…\" 2>/dev/null || cd \"$HOME\"; (setsid nohup opencode web --port 4096 > /tmp/o.log 2>&1 < /dev/null &) ; echo ok",
            "pkill -f \"opencode.*--port 4096\" ; echo done",
            "rm -rf \"…\"",
            "cat \"…\"",
            "test -f \"…\" && echo \"yes\" || echo \"no\"",
            "ls \"…\" 2>/dev/null | wc -l",
            "echo …",
            "sh -c 'apk add --quiet xz 2>/dev/null || true'",
            "sh -c 'rm -f \"…\" && xz -dc \"…\" > \"…\"'",
            "export P=\"$NATIVE_DIR/libproot.so\"\n$P --kill-on-exit -r /x /bin/sh -c 'uname -a'",
            "proot -0 -b /sdcard -r \"…\" -w /root /bin/sh -l",
            "$PREFIX/bin/node server.js",
            "sh",
            "sudo apk add git",
            "python3 -c 'print(1)'",
            "sed -i 's/a/b/' f",
            "find . -name '*.tmp' -delete",
            "xargs rm -f",
        ] {
            assert_eq!(tier(command), Tier::Program, "{command}");
        }
    }

    #[test]
    fn hidden_commands_are_opaque() {
        for command in [
            "…",
            "…\n",
            "sh -c …",
            "bash -lc \"…\"",
            "eval …",
            "node -e \"…\"",
            "echo 'ls' | sh",
            "cat x.py | python3",
            "$CMD --flag",
            "echo ok; …",
            "X=$(…)",
            "cd /tmp && sh -c \"$(echo …)\"",
            "sh -c 'cd /x && …'",
            "ARGS=\"-b /sdcard\"; $PROOT $ARGS … -c \"ls\"",
            "proot -r /x \"…\" -c 'ls'",
        ] {
            assert_eq!(tier(command), Tier::Opaque, "{command}");
        }
    }

    #[test]
    fn opaque_reason_is_specific() {
        assert_eq!(
            assess("sh -c …").reason,
            "`sh -c` runs a script built at runtime"
        );
        assert_eq!(assess("echo hi | bash").reason, "pipes text into a shell");
        assert!(assess("sh").opens_shell);
        assert!(assess("cd /x && bash -l").opens_shell);
        assert!(!assess("python3 driver.py").opens_shell);
    }
}
