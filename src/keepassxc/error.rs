use std::fmt;
use std::io;
use std::path::PathBuf;

/// Everything that can go wrong while talking to KeePassXC.
///
/// An error type needs two trait impls: `Display` (the message shown to
/// users) and `std::error::Error` (marks it as an error and exposes the
/// underlying cause through `source`). The `From` impls below let the `?`
/// operator convert those error types into ours automatically.
#[derive(Debug)]
pub enum Error {
    SocketNotFound(PathBuf),
    Connect(io::Error),
    Io(io::Error),
    Json(serde_json::Error),
    Base64(base64::DecodeError),
    Protocol(String),
    /// KeePassXC answered with an error object. `code` is kept as the raw
    /// string; the `is_*` helpers below name the codes seen so far.
    Remote {
        code: String,
        message: String,
    },
    Crypto,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SocketNotFound(path) => write!(
                f,
                "KeePassXC socket not found at {}. Is KeePassXC running with browser integration enabled?",
                path.display()
            ),
            Error::Connect(e) => write!(f, "cannot connect to KeePassXC: {e}"),
            Error::Io(e) => write!(f, "I/O error while talking to KeePassXC: {e}"),
            Error::Json(e) => write!(f, "invalid JSON from KeePassXC: {e}"),
            Error::Base64(e) => write!(f, "invalid base64 from KeePassXC: {e}"),
            Error::Protocol(msg) => write!(f, "unexpected response from KeePassXC: {msg}"),
            Error::Remote { code, message } => {
                write!(f, "KeePassXC returned error {code}: {message}")
            }
            Error::Crypto => write!(f, "encryption or decryption failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Connect(e) | Error::Io(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::Base64(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64(e)
    }
}

/// KeePassXC error codes seen so far (verified live, see `docs/design.md`).
const CODE_DATABASE_LOCKED: &str = "1";
const CODE_ASSOCIATION_FAILED: &str = "8";
const CODE_NO_LOGINS: &str = "15";

impl Error {
    fn remote_code(&self) -> Option<&str> {
        match self {
            Error::Remote { code, .. } => Some(code),
            _ => None,
        }
    }

    /// The active database is locked ("Database not opened").
    pub fn is_database_locked(&self) -> bool {
        self.remote_code() == Some(CODE_DATABASE_LOCKED)
    }

    /// The pairing is unknown to the active database. Also what you get when
    /// a different, unlocked database is active.
    pub fn is_association_failed(&self) -> bool {
        self.remote_code() == Some(CODE_ASSOCIATION_FAILED)
    }

    /// No entry has the requested URL.
    pub fn is_no_logins(&self) -> bool {
        self.remote_code() == Some(CODE_NO_LOGINS)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(code: &str) -> Error {
        Error::Remote {
            code: code.into(),
            message: "message".into(),
        }
    }

    #[test]
    fn each_code_is_recognized_only_by_its_own_helper() {
        let flags = |e: Error| {
            [
                e.is_database_locked(),
                e.is_association_failed(),
                e.is_no_logins(),
            ]
        };
        assert_eq!(flags(remote("1")), [true, false, false]);
        assert_eq!(flags(remote("8")), [false, true, false]);
        assert_eq!(flags(remote("15")), [false, false, true]);
        assert_eq!(flags(remote("2")), [false, false, false]);
        assert_eq!(flags(Error::Crypto), [false, false, false]);
    }

    #[test]
    fn messages_include_the_remote_code_and_the_socket_path() {
        assert_eq!(
            remote("15").to_string(),
            "KeePassXC returned error 15: message"
        );
        let missing = Error::SocketNotFound(PathBuf::from("/run/x/socket"));
        assert!(missing.to_string().contains("/run/x/socket"));
    }

    #[test]
    fn io_errors_expose_their_cause() {
        use std::error::Error as _;
        let error = Error::from(io::Error::other("boom"));
        assert_eq!(error.source().unwrap().to_string(), "boom");
        assert!(Error::Crypto.source().is_none());
    }
}
