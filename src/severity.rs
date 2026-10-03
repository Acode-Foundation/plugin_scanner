use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL_DESC: [Self; 5] = [
        Self::Critical,
        Self::High,
        Self::Medium,
        Self::Low,
        Self::Info,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Info => "Info",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Archive,
    Manifest,
    Shell,
    Native,
    Tampering,
    DynamicCode,
    Network,
    Filesystem,
    Storage,
    AcodeApi,
    Obfuscation,
}

impl Category {
    pub const ALL: [Self; 11] = [
        Self::Archive,
        Self::Manifest,
        Self::Shell,
        Self::Native,
        Self::Tampering,
        Self::DynamicCode,
        Self::Network,
        Self::Filesystem,
        Self::Storage,
        Self::AcodeApi,
        Self::Obfuscation,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Manifest => "manifest",
            Self::Shell => "shell",
            Self::Native => "native",
            Self::Tampering => "tampering",
            Self::DynamicCode => "dynamic_code",
            Self::Network => "network",
            Self::Filesystem => "filesystem",
            Self::Storage => "storage",
            Self::AcodeApi => "acode_api",
            Self::Obfuscation => "obfuscation",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Archive => "Archive integrity",
            Self::Manifest => "Manifest",
            Self::Shell => "Shell command execution",
            Self::Native => "Android / Cordova native access",
            Self::Tampering => "Acode or other-plugin tampering",
            Self::DynamicCode => "Dynamic or remote code",
            Self::Network => "Network access",
            Self::Filesystem => "File system access",
            Self::Storage => "Browser storage",
            Self::AcodeApi => "Acode APIs and hooks",
            Self::Obfuscation => "Obfuscation",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Archive => {
                "the zip is malformed or built so the installer and scanner see different files"
            }
            Self::Manifest => "plugin.json problems that break installing or publishing",
            Self::Shell => {
                "can run shell commands in the terminal environment or load native libraries"
            }
            Self::Native => "calls Android / Cordova native plugins directly",
            Self::Tampering => "changes Acode itself, core modules, or other installed plugins",
            Self::DynamicCode => {
                "builds, decodes, or downloads code at runtime that reviewers can't see"
            }
            Self::Network => "contacts remote servers",
            Self::Filesystem => "reads or writes files through Acode, SD card, or System APIs",
            Self::Storage => "uses localStorage, IndexedDB, or cookies",
            Self::AcodeApi => "uses Acode lifecycle, modules, commands, and editor state",
            Self::Obfuscation => "code is deliberately hard to read",
        }
    }
}
