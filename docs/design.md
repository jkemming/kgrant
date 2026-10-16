# Design

`kgrant` reads secrets from a running KeePassXC through its browser-integration protocol: `kgrant get <entry> <field>...`.

The goals:

- The master password is entered once, in KeePassXC.
- Programs request specific fields of specific entries at runtime, and the user approves or denies each request in KeePassXC.
- There is no other credential store for programs to read.
- Secrets are never exported into a long-lived shell.

## How it talks to KeePassXC

`kgrant` uses the browser-integration native-messaging socket, the same channel browser extensions use.

- On Linux, the socket is `$XDG_RUNTIME_DIR/app/org.keepassxc.KeePassXC/org.keepassxc.KeePassXC.BrowserServer`, falling back to `$XDG_RUNTIME_DIR/org.keepassxc.KeePassXC.BrowserServer`. On macOS, it is `org.keepassxc.KeePassXC.BrowserServer` inside the OS-provided per-user temporary directory (`getconf DARWIN_USER_TEMP_DIR`), independent of `XDG_RUNTIME_DIR` and overrides to `TMPDIR` (verified against KeePassXC's [socket-path implementation](https://github.com/keepassxreboot/keepassxc/blob/develop/src/browser/BrowserShared.cpp)). Messages are bare JSON objects with no length prefix.
- Every connection makes a fresh session keypair (`change-public-keys`). Messages are NaCl `crypto_box` with a random 24-byte nonce (base64). The response nonce is the request nonce plus one (little-endian with carry, like libsodium's `sodium_increment`).
- Inner responses carry `"success": "true"` as a string, but `get-logins` returns `count` as a number.
- KeePassXC also sends unsolicited `database-locked` and `database-unlocked` messages. The client skips any message that is not the reply to its request.

### Pairing

- `associate` takes the session public key and a new *identification public key* (`idKey`). KeePassXC shows a dialog, and the `id` it returns is the name the user typed there. The client does not send a connection name.
- KeePassXC stores the identification key in the database's custom data (`KPXC_BROWSER_<id>`). The client keeps only the `id` and the public key. `test-associate` accepts exactly that, which makes the key a **bearer token**: anything that can read it can use the pairing.
- A pairing can be revoked in KeePassXC's browser-integration settings for the database.

### `get-logins`

- It matches a URL and returns `count` and `entries[]` with `group`, `login`, `name`, `password`, `stringFields` and `uuid` (32 hex digits, no dashes). A confirmation dialog appears, with allow/deny and a "remember" choice.
- `stringFields` holds only the attributes whose key starts with `KPH: `, and only if the setting "Return also advanced string fields which start with \"KPH: \"" is on in the browser-integration settings. Each element is an object with one field, `[{"KPH: Token": "..."}]`, the name with its prefix.
- KeePassXC resolves placeholders in a value before returning it: `{USERNAME}` and `{PASSWORD}` give the standard fields. References (`{REF:...}`) in the password and username resolve the same way. Other placeholders such as `{S:Other Field}` should too, but that was not tried.
- Several entries with the same URL are all returned (`count` 2, in no particular order). `kgrant` treats more than one match as an error instead of taking the first.
- A denied request ("Deny All") is **not an error**: `success: "true"` with `count` 0 and an empty `entries`. A client cannot tell a denial from an entry it may not read.
- A URL with no matching entry is an error: `errorCode` `"15"`, `error` `"No logins found"`.
- `get-logins` only searches the active database, unless "Search in all opened databases" is on. Then it searches every open database for which one of the request's `keys` matches the pairing stored there (by key value). `kgrant` therefore sends all stored associations in `keys`. The connection must still pass `test-associate` against the *active* database first, so the active database has to be paired too. Matches in several databases count as several matches. (Read from the 2.7.12 source, not tried live.)

### Failure modes

KeePassXC serves **whichever database is active**, and locking one switches to another open database.

- Active database locked, nothing else active: every request fails with `errorCode` `"1"`, `error` `"Database not opened"`. The session handshake still works.
- A different, unlocked database is active: `get-databasehash` succeeds with that database's hash, but `test-associate` fails with `errorCode` `"8"`, `error` `"KeePassXC association failed, try again"`, because the pairing is not registered there.
- KeePassXC not running: the socket file is missing, or stale and connecting gives `ECONNREFUSED`.

Everything above was checked against KeePassXC 2.7.12 with the test database ([testing.md](testing.md)), except where stated. Flatpak builds use a different socket path, which is unverified.

KeePassXC's `develop` branch has a `get-database-entries` action (titles, UUIDs and URLs of all entries, no per-entry confirmation), but it is in no release and is refused unless an opt-in setting is on. `kgrant` does not call it.

## Database convention

Existing entries are used as they are. Two additions on the entries that are to be read:

1. The URL `kgrant://<entry>`, where `<entry>` is the name of the entry in kebab-case: lower case, every character that is not a letter or digit becomes `-`, repeated `-` collapse, none at the ends. `Multi-Field` is `kgrant://multi-field`, `Test / Mine & your entry` is `kgrant://test-mine-your-entry`. It goes in an *additional URL* of the entry (KeePassXC stores it as the attribute `KP2A_URL`), not in the main URL field, which keeps the real URL of the entry. KeePassXC does the matching, so `kgrant` does not care where the URL is. The title of the entry is never used.
2. A custom field `KPH: <field>` for each value to export, e.g. `KPH: Access Key ID`. A placeholder such as `{REF:...}` or `{S:Other Field}` as its value avoids duplicating a value. Only such fields are used: the password and the user name of the entry are not read, so an entry can be exposed without exposing its password.

Entry names are a flat namespace chosen by hand, and two entries must not share a slug (that is an error).

## Lookup

`kgrant get Multi-Field Token User --json` turns the entry name into `kgrant://multi-field`, calls `get-logins` once, and picks the fields `KPH: Token` and `KPH: User` out of `stringFields`. It makes one request per entry, however many fields, so KeePassXC asks for one confirmation, not one per field. `Secrets::read_many` takes any number of `(entry, field)` pairs, groups them by entry and returns the values in the order asked.

## Interface

- `kgrant get <ENTRY> <FIELD>...`: with one field it prints the value as it is. With several fields you need `--json`, which prints an object from field name to value, so values with line breaks stay intact. Without `--json` the command refuses before asking KeePassXC for anything. The field name is given without the `KPH: ` prefix and matched exactly, case included.
- `kgrant pair`: the one-time pairing.
- Every failure exits with status 1 and says what to do: not paired, KeePassXC not running, locked, wrong database active, no entry with that URL, denied or inaccessible, several entries with the URL, the entry has no such field (with the fields it has, or a hint at the setting if none were returned). The mapping from KeePassXC's error codes is in `src/secrets.rs`, the code names in `src/keepassxc/error.rs`.

## Security model

- The security gate is **KeePassXC's per-entry confirmation**, not the stored association key. Any process running as the user can read the key file, so treat it as a bearer token.
- Every entry with a `kgrant://` URL is readable by any paired client, and all its `KPH: ` fields come with the one request, even those not asked for (only the asked ones are used and printed).
- Keep confirmation always on for high-value entries (cloud credentials, private keys, the login password). "Remember" only for low-value ones.
- `kgrant get` prints the value to stdout, so whatever captures stdout holds it. Values are not zeroized in memory, but the process is short-lived and exits right after printing.
- KeePassXC answers for the active database, so with several databases open a request can reach one the user did not intend. Pairing is per database, so an unpaired database refuses (error code 8).

### Association file

A plain file, mode `0600`, at `$XDG_STATE_HOME/kgrant/association.json` (directory `0700`), created with the right permissions from the start.

- Content: a JSON list with one association per paired database. `kgrant get` tries each against the active database and uses the one it accepts (the others fail with error code 8). `kgrant pair` adds to the list and refuses if the active database is already paired. Every pairing gets its own random key, so the same connection name can be used in several databases, and `kgrant` never looks pairings up by name.
- The file is replaced atomically (temp file plus rename). Removing a pairing means editing the file by hand.
- `kgrant` refuses to run if the permissions are looser than `0600` (like `ssh`).
- Keep it out of dotfiles trees and other git repositories.
- Pair per host with a distinctive name (e.g. `<host>/kgrant`), typed in KeePassXC's pairing dialog.
