use std::path::PathBuf;

/// Product naming lives here so branding can change without code edits
/// elsewhere in the service.
#[cfg_attr(not(windows), allow(dead_code))]
pub const PRODUCT_DIR: &str = "GamblingGuard";

#[derive(Debug, Clone)]
pub struct DataPaths {
    pub root: PathBuf,
}

impl DataPaths {
    /// `%ProgramData%\GamblingGuard` on Windows. Elsewhere (development),
    /// `$GG_DATA_DIR` or `./gg-data`. `GG_DATA_DIR` overrides on all
    /// platforms for testing.
    pub fn resolve() -> Self {
        if let Some(dir) = std::env::var_os("GG_DATA_DIR") {
            return Self { root: dir.into() };
        }
        #[cfg(windows)]
        {
            let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
            Self {
                root: PathBuf::from(base).join(PRODUCT_DIR),
            }
        }
        #[cfg(not(windows))]
        {
            Self {
                root: PathBuf::from("gg-data"),
            }
        }
    }

    pub fn rules_dir(&self) -> PathBuf {
        self.root.join("rules")
    }
    pub fn settings(&self) -> PathBuf {
        self.root.join("settings.json")
    }
    pub fn status(&self) -> PathBuf {
        self.root.join("status.json")
    }
}
