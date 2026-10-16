//! The command line: what `kgrant` accepts, and which command runs.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::CompleteEnv;

use crate::Result;
use crate::secret::Secret;
use crate::secrets::{self, Secrets};

// `clap` derives the argument parsing, `--help` text and error messages from
// these types: each variant is a subcommand, each field an argument, and the
// doc comments become the help text.

/// Read secrets from KeePassXC, with the approval of the user.
#[derive(Parser)]
#[command(name = "kgrant", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print fields of an entry (the entry with the URL kgrant://<ENTRY in kebab-case>)
    Get {
        /// Name of the entry, e.g. `Multi-Field` (looks for the URL `kgrant://multi-field`)
        entry: String,
        /// Names of the fields without the `KPH: ` prefix, e.g. `Access Key ID`. One field
        /// prints its value, several need --json
        #[arg(required = true)]
        fields: Vec<String>,
        /// Print a JSON object from field name to value (needed for several fields, keeps
        /// line breaks intact)
        #[arg(long)]
        json: bool,
    },
    /// Pair this machine with the open KeePassXC database (once per machine)
    Pair,
}

/// Runs `kgrant` with these arguments (the first is the program name) and
/// returns its exit status. Errors are printed here: returning one from `main`
/// would print its `Debug` form (strings in quotes), so the `Display` message
/// is printed instead.
///
/// When the shell asks for completions (`COMPLETE=<shell> kgrant ...`, which is
/// what the line `COMPLETE=fish kgrant | source` sets up), this answers and
/// exits the process, using the real process arguments instead of `args`.
pub fn run(
    args: impl IntoIterator<Item = impl Into<OsString> + Clone>,
    secrets: &dyn Secrets,
) -> ExitCode {
    CompleteEnv::with_factory(Cli::command).complete();
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            // `--help` and `--version` come out as "errors" too, with status 0.
            let _ = e.print();
            return ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(2));
        }
    };
    match dispatch(cli.command, secrets) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(command: Command, secrets: &dyn Secrets) -> Result<()> {
    match command {
        Command::Get {
            entry,
            fields,
            json,
        } => {
            let text = get(&entry, &fields, json, secrets)?;
            // `writeln!` returns an error on a closed pipe, where `println!`
            // would panic.
            writeln!(io::stdout(), "{text}")?;
            Ok(())
        }
        Command::Pair => secrets::pair(),
    }
}

/// What `kgrant get` prints.
fn get(entry: &str, fields: &[String], json: bool, secrets: &dyn Secrets) -> Result<String> {
    let wanted: Vec<Secret> = fields
        .iter()
        .map(|field| Secret::parse(entry, field))
        .collect::<std::result::Result<_, _>>()?;
    let distinct: std::collections::BTreeSet<&str> = fields.iter().map(String::as_str).collect();
    if distinct.len() > 1 && !json {
        return Err(format!(
            "{} fields need --json, which prints them as an object (one field prints its value)",
            distinct.len()
        )
        .into());
    }

    let values = secrets.read_many(&wanted)?;
    if json {
        let object: BTreeMap<&str, &str> = fields
            .iter()
            .map(String::as_str)
            .zip(values.iter().map(String::as_str))
            .collect();
        Ok(serde_json::to_string(&object)?)
    } else {
        Ok(values.into_iter().next().expect("one field is required"))
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use crate::secrets::StaticSecrets;

    use super::*;

    fn fields(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    fn sample() -> StaticSecrets {
        StaticSecrets::new([
            ("multi-field", "user", "alice"),
            ("multi-field", "token", "line one\nline two"),
        ])
    }

    #[test]
    fn get_prints_one_field_as_it_is() {
        let text = get("Multi-Field", &fields(&["user"]), false, &sample()).unwrap();
        assert_eq!(text, "alice");
        let text = get("Multi-Field", &fields(&["token"]), false, &sample()).unwrap();
        assert_eq!(text, "line one\nline two");
    }

    #[test]
    fn get_prints_several_fields_as_json_and_keeps_line_breaks() {
        let text = get("Multi-Field", &fields(&["user", "token"]), true, &sample()).unwrap();
        let object: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(object["user"], "alice");
        assert_eq!(object["token"], "line one\nline two");
        assert_eq!(object.as_object().unwrap().len(), 2);
    }

    #[test]
    fn get_prints_one_field_as_json_when_asked() {
        let text = get("Multi-Field", &fields(&["user"]), true, &sample()).unwrap();
        assert_eq!(text, r#"{"user":"alice"}"#);
    }

    #[test]
    fn get_refuses_several_fields_without_json_before_asking_for_anything() {
        let asked = std::cell::Cell::new(false);
        let secrets = |_: &[Secret]| -> Result<Vec<String>> {
            asked.set(true);
            Ok(vec![])
        };
        let error = get("Multi-Field", &fields(&["user", "token"]), false, &secrets)
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("2 fields need --json"), "{error}");
        assert!(!asked.get());
    }

    #[test]
    fn asking_for_the_same_field_twice_is_one_field() {
        let text = get("Multi-Field", &fields(&["user", "user"]), false, &sample()).unwrap();
        assert_eq!(text, "alice");
    }

    #[test]
    fn get_turns_the_name_of_the_entry_into_the_slug_and_rejects_nothing_to_make_one_of() {
        // `Multi Field` and `multi_field` are the entry `multi-field`.
        let secrets = StaticSecrets::new([("multi-field", "user", "alice")]);
        for name in ["Multi-Field", "Multi Field", "multi_field", "MULTI / FIELD"] {
            assert_eq!(
                get(name, &fields(&["user"]), false, &secrets).unwrap(),
                "alice"
            );
        }
        let error = get(" / & ", &fields(&["user"]), false, &secrets)
            .unwrap_err()
            .to_string();
        assert!(error.contains("no letters or digits"), "{error}");
        let error = get("x", &fields(&[""]), false, &secrets)
            .unwrap_err()
            .to_string();
        assert!(error.contains("field name is empty"), "{error}");
    }

    #[test]
    fn get_reads_through_the_secrets_it_is_given() {
        let secrets = sample();
        assert!(get("multi-field", &fields(&["user"]), false, &secrets).is_ok());
        assert!(get("multi-field", &fields(&["unknown"]), false, &secrets).is_err());
    }

    fn parse(args: &[&str]) -> std::result::Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("kgrant").chain(args.iter().copied()))
    }

    #[test]
    fn the_command_line_definition_is_consistent() {
        // Catches conflicting flags, duplicate names and the like at test time.
        Cli::command().debug_assert();
    }

    #[test]
    fn get_needs_an_entry_and_a_field() {
        assert!(parse(&["get"]).is_err());
        assert!(parse(&["get", "Default"]).is_err());
        assert!(parse(&["get", "Default", "Token"]).is_ok());
        assert!(parse(&["get", "Default", "Token", "User", "--json"]).is_ok());
        assert!(parse(&["get", "--json", "Default", "Token"]).is_ok());
        assert!(parse(&["pair"]).is_ok());
    }

    #[test]
    fn unknown_commands_are_rejected() {
        assert!(parse(&["nope"]).is_err());
        assert!(parse(&[]).is_err());
    }
}
