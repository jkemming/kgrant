//! The association file: the `id` and identification key from each pairing.
//!
//! Kept as a plain file with mode `0600` (see `docs/design.md`). Like `ssh`,
//! loading refuses a file that other users could read. It holds one
//! association per paired database.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::keepassxc::Association;

use crate::Result;

/// `$XDG_STATE_HOME/kgrant/association.json`, defaulting to `~/.local/state`.
pub fn association_path() -> Result<PathBuf> {
    association_path_in(std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME"))
}

/// Takes the environment variables as arguments so tests need not change the
/// process environment.
fn association_path_in(state: Option<OsString>, home: Option<OsString>) -> Result<PathBuf> {
    let state = match state.filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(home.ok_or("neither XDG_STATE_HOME nor HOME is set")?)
            .join(".local/state"),
    };
    Ok(state.join("kgrant/association.json"))
}

/// Reads all associations; the list is empty if the file does not exist.
pub fn load(path: &Path) -> Result<Vec<Association>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot open {}: {e}", path.display()).into()),
    };

    // Check the permissions of the file we actually opened (not the path), so
    // it cannot be swapped between the check and the read.
    let mode = file.metadata()?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "{} has permissions {mode:03o}, which let other users read it. Run `chmod 600 {}`",
            path.display(),
            path.display()
        )
        .into());
    }

    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("{} is not a valid association file: {e}", path.display()).into())
}

/// Adds an association to the file, creating it and its `0700` directory as
/// needed. Several associations may share an `id`: the name is only unique
/// within one database, and each has its own key.
pub fn add(path: &Path, association: Association) -> Result<()> {
    let mut associations = load(path)?;
    associations.push(association);
    write(path, &associations)
}

/// Replaces the file atomically: the new content is written next to it and
/// renamed over it, so a crash cannot leave a half-written file.
fn write(path: &Path, associations: &[Association]) -> Result<()> {
    if let Some(dir) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }

    let temp = path.with_extension("json.tmp");
    match fs::remove_file(&temp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            return Err(format!("cannot remove {}: {e}", temp.display()).into());
        }
        _ => {}
    }
    // `mode(0o600)` applies at creation, so the key is never readable by
    // others, not even briefly.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| format!("cannot create {}: {e}", temp.display()))?;
    file.write_all(serde_json::to_string_pretty(associations)?.as_bytes())?;
    fs::rename(&temp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str) -> Association {
        Association {
            id: id.into(),
            key: "key".into(),
        }
    }

    fn ids(associations: &[Association]) -> Vec<&str> {
        associations.iter().map(|a| a.id.as_str()).collect()
    }

    #[test]
    fn add_then_load_roundtrips_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kgrant/association.json");
        add(&path, sample("test")).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let loaded = load(&path).unwrap();
        assert_eq!(ids(&loaded), ["test"]);
        assert_eq!(loaded[0].key, "key");
    }

    #[test]
    fn add_keeps_earlier_associations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("association.json");
        add(&path, sample("one")).unwrap();
        add(&path, sample("two")).unwrap();

        assert_eq!(ids(&load(&path).unwrap()), ["one", "two"]);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn add_allows_the_same_id_for_different_databases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("association.json");
        add(&path, sample("aitne/cli")).unwrap();
        let mut other = sample("aitne/cli");
        other.key = "other-key".into();
        add(&path, other).unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(ids(&loaded), ["aitne/cli", "aitne/cli"]);
        assert_ne!(loaded[0].key, loaded[1].key);
    }

    #[test]
    fn load_returns_nothing_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(&dir.path().join("nope.json")).unwrap().is_empty());
    }

    #[test]
    fn load_refuses_loose_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("association.json");
        add(&path, sample("test")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let error = load(&path).unwrap_err().to_string();
        assert!(error.contains("chmod 600"), "{error}");
    }

    #[test]
    fn load_refuses_every_kind_of_group_or_world_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("association.json");
        add(&path, sample("test")).unwrap();
        for mode in [0o640, 0o604, 0o660, 0o666, 0o644] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(load(&path).is_err(), "mode {mode:o} should be refused");
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(load(&path).is_ok());
    }

    #[test]
    fn load_reports_a_file_that_is_not_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("association.json");
        fs::write(&path, "not json").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&path).is_err());
    }

    #[test]
    fn add_creates_a_private_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/kgrant/association.json");
        add(&path, sample("test")).unwrap();
        let mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn add_replaces_a_temporary_file_left_by_a_crash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("association.json");
        fs::write(path.with_extension("json.tmp"), "half written").unwrap();
        add(&path, sample("test")).unwrap();
        assert_eq!(ids(&load(&path).unwrap()), ["test"]);
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn path_follows_xdg_state_home_and_falls_back_to_home() {
        let var = |s: &str| Some(OsString::from(s));
        assert_eq!(
            association_path_in(var("/state"), var("/home/u")).unwrap(),
            PathBuf::from("/state/kgrant/association.json")
        );
        for state in [None, var("")] {
            assert_eq!(
                association_path_in(state, var("/home/u")).unwrap(),
                PathBuf::from("/home/u/.local/state/kgrant/association.json")
            );
        }
        assert!(association_path_in(None, None).is_err());
    }
}
