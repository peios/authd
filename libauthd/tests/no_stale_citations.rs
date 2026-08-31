//! The PSD-NNN series was retired when the specifications were reorganised
//! into the PCSA books (PCDS/PGSS/PSPK/PSPU) and the TRMs; a citation to it
//! names a document that no longer exists (PEI-301). This walk keeps one
//! from creeping back in — cite the current home instead: PGSS/PSPU
//! sections, PCDS sections, or "Kernel TRM §…".

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("libauthd sits in the workspace root")
        .to_path_buf()
}

fn offending(dir: &Path, hits: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name();
            if name != "target" && name != "out" && name != ".git" {
                offending(&path, hits);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            for (index, line) in text.lines().enumerate() {
                // Written split so this file does not match itself.
                if line.contains(&format!("{}-0", "PSD")) || line.contains(&format!("{}-9", "PSD"))
                {
                    hits.push(format!("{}:{}", path.display(), index + 1));
                }
            }
        }
    }
}

#[test]
fn no_source_file_cites_the_retired_psd_series() {
    let mut hits = Vec::new();
    offending(&workspace_root(), &mut hits);
    assert!(
        hits.is_empty(),
        "stale PSD-NNN citations (the series was retired; cite PCSA books or the TRMs):\n{}",
        hits.join("\n")
    );
}
