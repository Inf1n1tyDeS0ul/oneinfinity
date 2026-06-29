// corpus_manager.rs — persistent corpus storage and distillation
//
// Manages on-disk corpus of fuzzing inputs.  Each input is stored as
// <sha256_hex>.bin under `corpus_dir`.  Distillation uses a length-based
// heuristic: among inputs that share the same first-4-hex-chars of their
// sha256 digest (i.e. first 2 bytes), keep only the longest one.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// CorpusManager
// ---------------------------------------------------------------------------

pub struct CorpusManager {
    corpus_dir: PathBuf,
}

impl CorpusManager {
    /// Create a new CorpusManager rooted at `corpus_dir`.  The directory is
    /// created (including parents) on construction if it does not yet exist.
    pub fn new(corpus_dir: &Path) -> Self {
        if let Err(e) = fs::create_dir_all(corpus_dir) {
            eprintln!("[corpus_manager] could not create corpus dir {:?}: {e}", corpus_dir);
        }
        Self { corpus_dir: corpus_dir.to_path_buf() }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Load all `.bin` files from `corpus_dir` and return their contents.
    /// Silently skips entries that cannot be read.
    pub fn load(&self) -> Vec<Vec<u8>> {
        let entries = match fs::read_dir(&self.corpus_dir) {
            Ok(e) => e,
            Err(_) => return vec![],
        };
        let mut result = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("bin") {
                match fs::read(&path) {
                    Ok(data) => result.push(data),
                    Err(e) => eprintln!("[corpus_manager] failed to read {:?}: {e}", path),
                }
            }
        }
        result
    }

    /// Persist `input` to `corpus_dir/<sha256>.bin`.
    /// No-ops silently if the file already exists.
    pub fn save(&self, input: &[u8]) {
        let hex = Self::sha256_hex(input);
        let path = self.corpus_dir.join(format!("{hex}.bin"));
        if path.exists() {
            return;
        }
        match fs::File::create(&path) {
            Ok(mut f) => {
                if let Err(e) = f.write_all(input) {
                    eprintln!("[corpus_manager] write error for {:?}: {e}", path);
                }
            }
            Err(e) => eprintln!("[corpus_manager] create error for {:?}: {e}", path),
        }
    }

    /// Distill the on-disk corpus using a greedy heuristic:
    /// Among all `.bin` files whose sha256 filename shares the same first
    /// 4 hex characters (first 2 bytes of hash), keep only the longest
    /// one and delete the rest.
    ///
    /// Returns `(before, after)` — count of inputs before and after.
    pub fn distill(&self) -> (usize, usize) {
        let entries = match fs::read_dir(&self.corpus_dir) {
            Ok(e) => e,
            Err(_) => return (0, 0),
        };

        // Collect (hex_name, file_len, path)
        let mut files: Vec<(String, u64, PathBuf)> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("bin") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    files.push((stem.to_owned(), len, path));
                }
            }
        }

        let before = files.len();

        // Group by first 4 hex chars (2 bytes of sha256 prefix).
        // Use a simple sort: sort by prefix then by length desc so the first
        // item per group is always the longest.
        files.sort_by(|a, b| {
            let pa = &a.0[..a.0.len().min(4)];
            let pb = &b.0[..b.0.len().min(4)];
            pa.cmp(pb).then(b.1.cmp(&a.1)) // desc length within prefix group
        });

        let mut kept: usize = 0;
        let mut current_prefix = String::new();
        let mut group_has_keeper = false;

        for (hex, _len, path) in &files {
            let prefix = hex[..hex.len().min(4)].to_owned();
            if prefix != current_prefix {
                current_prefix = prefix;
                group_has_keeper = false;
            }
            if !group_has_keeper {
                // Keep the first (longest) entry in this prefix group.
                group_has_keeper = true;
                kept += 1;
            } else {
                // Remove duplicates within the same prefix group.
                if let Err(e) = fs::remove_file(path) {
                    eprintln!("[corpus_manager] failed to remove {:?}: {e}", path);
                }
            }
        }

        (before, kept)
    }

    /// Emit a `corpus_distilled` NDJSON event to stdout.
    pub fn emit_distillation_event(&self, before: usize, after: usize) {
        println!(
            "{{\"type\":\"corpus_distilled\",\"before\":{before},\"after\":{after}}}"
        );
    }
}
