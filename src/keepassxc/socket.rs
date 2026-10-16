#[cfg(any(not(target_os = "macos"), test))]
use std::path::Path;
use std::path::PathBuf;

const SOCKET_NAME: &str = "org.keepassxc.KeePassXC.BrowserServer";

/// Where KeePassXC listens, if the platform's runtime directory is available.
///
/// macOS uses the OS-provided per-user temporary directory. Other Unix systems
/// use `$XDG_RUNTIME_DIR`, preferring `app/org.keepassxc.KeePassXC/<name>` over
/// the plain runtime-dir path. Flatpak builds differ (unverified).
pub fn default_socket_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::{CString, OsString};
        use std::os::unix::ffi::OsStringExt;

        let length =
            unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, std::ptr::null_mut(), 0) };
        if length == 0 {
            return None;
        }
        let mut buffer = vec![0_u8; length];
        let written = unsafe {
            libc::confstr(
                libc::_CS_DARWIN_USER_TEMP_DIR,
                buffer.as_mut_ptr().cast(),
                length,
            )
        };
        if written == 0 || written > length {
            return None;
        }
        buffer.truncate(written);
        let directory = CString::from_vec_with_nul(buffer).ok()?;
        Some(PathBuf::from(OsString::from_vec(directory.into_bytes())).join(SOCKET_NAME))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(socket_path_in(&PathBuf::from(std::env::var_os(
            "XDG_RUNTIME_DIR",
        )?)))
    }
}

#[cfg(any(not(target_os = "macos"), test))]
fn socket_path_in(runtime: &Path) -> PathBuf {
    let nested = runtime
        .join("app/org.keepassxc.KeePassXC")
        .join(SOCKET_NAME);
    if nested.exists() {
        nested
    } else {
        runtime.join(SOCKET_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_is_in_the_runtime_directory_by_default() {
        let runtime = tempfile::tempdir().unwrap();
        assert_eq!(
            socket_path_in(runtime.path()),
            runtime.path().join(SOCKET_NAME)
        );
    }

    #[test]
    fn socket_in_the_app_subdirectory_is_preferred_when_it_exists() {
        let runtime = tempfile::tempdir().unwrap();
        let nested = runtime.path().join("app/org.keepassxc.KeePassXC");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join(SOCKET_NAME), "").unwrap();
        assert_eq!(socket_path_in(runtime.path()), nested.join(SOCKET_NAME));
    }
}
