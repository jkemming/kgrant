use std::io;

use crate::Result;
use crate::keepassxc::{Association, Client, Error};

/// The stored association that the active database accepts, if any.
///
/// KeePassXC only knows the pairings of its own database and rejects the
/// others (error code 8), so each is tried in turn. The returned reference
/// borrows from `associations`, which the lifetime `'a` expresses.
pub(super) fn active_association<'a>(
    client: &mut Client,
    associations: &'a [Association],
) -> Result<Option<&'a Association>> {
    for association in associations {
        match client.test_associate(association) {
            Ok(()) => return Ok(Some(association)),
            Err(e) if e.is_association_failed() => {}
            Err(e) => return Err(explain(e)),
        }
    }
    Ok(None)
}

pub(super) fn connect() -> Result<Client> {
    let socket = crate::keepassxc::default_socket_path().ok_or(
        "cannot determine the KeePassXC socket directory; on Linux, check XDG_RUNTIME_DIR",
    )?;
    Client::connect(&socket).map_err(explain)
}

/// Turns a protocol error into a message that says what to do about it.
pub(super) fn explain(error: Error) -> Box<dyn std::error::Error> {
    match &error {
        Error::SocketNotFound(_) => {
            "KeePassXC is not running, or browser integration is disabled in its settings".into()
        }
        Error::Connect(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            "KeePassXC is not running (stale socket)".into()
        }
        e if e.is_database_locked() => {
            "KeePassXC is locked; unlock the database and try again".into()
        }
        e if e.is_association_failed() => "the active KeePassXC database is not paired with \
             this machine; switch to the right database, or run `kgrant pair` for this one"
            .into(),
        _ => Box::new(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_says_what_to_do_about_known_errors() {
        let text = |e: Error| explain(e).to_string();
        let remote = |code: &str| Error::Remote {
            code: code.into(),
            message: "m".into(),
        };
        assert!(text(Error::SocketNotFound("/x".into())).contains("not running"));
        assert!(
            text(Error::Connect(io::ErrorKind::ConnectionRefused.into())).contains("stale socket")
        );
        assert!(text(remote("1")).contains("locked"));
        assert!(text(remote("8")).contains("kgrant pair"));
    }

    #[test]
    fn explain_keeps_the_message_of_other_errors() {
        let error = Error::Remote {
            code: "5".into(),
            message: "m".into(),
        };
        assert_eq!(explain(error).to_string(), "KeePassXC returned error 5: m");
        let other = Error::Connect(io::ErrorKind::PermissionDenied.into());
        assert!(explain(other).to_string().starts_with("cannot connect"));
    }
}
