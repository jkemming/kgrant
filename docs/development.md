# Development

## Layout

One package, `kgrant`, with a library and the CLI binary.

- `src/main.rs`: the composition root. It picks the real source of secrets and calls `run`.
- `src/cli.rs`: the command line (`clap`).
- `src/secrets.rs`: the `Secrets` trait and `StaticSecrets`. Its submodules are `lookup.rs` (the KeePassXC lookup), `pairing.rs` (`kgrant pair`), `connection.rs` (connecting, finding the accepted pairing and error messages) and `testing.rs` (test helpers).
- `src/secret.rs`: the `Secret` type and `entry_slug`.
- `src/store.rs`: the association file.
- `src/keepassxc/`: the protocol client, which does not depend on the rest of the crate. `client.rs` holds the session (`Client`, `Association`), `wire.rs` the messages on the socket, `login.rs` the `get-logins` entries, `socket.rs` the socket path and `error.rs` the errors. `fake.rs` is a fake KeePassXC on a temporary socket, used only in tests.

## Checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
mise run test
```

CI runs these on Linux and macOS. It also builds the test database for manual testing (`mise run database:import`, which needs `fish` and `keepassxc-cli`), to check that the database definition and the task still work. The release workflow builds the production binary with `mise run build` (`--target <triple>` to cross-target).

## Tests

- The public API is documented (`#![deny(missing_docs)]`), and functions whose result must not be ignored are `#[must_use]`.
- Unit tests live in a `#[cfg(test)] mod tests` at the bottom of the file they test. `tests/` holds integration tests that use only the public API.
- Code that reads the environment or talks to the socket takes its inputs as arguments (`association_path_in`, `pair_with`, `lookup_many`), so it can be tested. Write new code the same way.
- The protocol client is tested against the fake KeePassXC, which does the real handshake and encryption. KeePassXC's own behavior is checked by hand, see [testing.md](testing.md).
- Protocol facts in [design.md](design.md) were checked against KeePassXC 2.7.12 unless it says otherwise. Verify anything else before relying on it, and record what you find there.

## Releasing

Run the *Release* workflow from the Actions tab on `main` and enter the version without the `v`, for example `0.2.0`. The workflow:

1. commits the version bump (`Cargo.toml` and `Cargo.lock`) to `main`,
2. runs the tests and builds binaries for Linux and macOS (x86_64 and aarch64),
3. creates the tag `v0.2.0` on that commit and a GitHub release with the binaries and generated notes.

The workflow pushes to `main`, so it needs a `main` without branch protection, or one that the Actions bot may bypass. If the tests or a build fail, the bump commit is already on `main` but there is no tag, so fix the problem and run the workflow again with the same version.
