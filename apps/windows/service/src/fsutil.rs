use std::io::Write;
use std::path::Path;

/// Write via a temporary file and rename, so readers never see a partially
/// written file and a crash mid-write leaves the previous version intact.
pub fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}
