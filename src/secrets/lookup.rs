use crate::keepassxc::{Association, Client, FIELD_PREFIX, Login};
use crate::secret::Secret;
use crate::{Result, store};

use super::connection::{active_association, connect, explain};

/// Entries are found by this scheme and the name of the entry in the form of
/// [`crate::entry_slug`].
const URL_SCHEME: &str = "kgrant://";

/// Looks up several secrets over one connection, in the order asked. KeePassXC
/// is asked about the pairing once, and each entry gets one request for all
/// the fields wanted from it, so it has one confirmation dialog. Fails on the
/// first secret that cannot be read.
pub(super) fn read_from_keepassxc(secrets: &[Secret]) -> Result<Vec<String>> {
    let path = store::association_path()?;
    let associations = store::load(&path)?;
    if associations.is_empty() {
        return Err("not paired with KeePassXC yet. Run `kgrant pair` first".into());
    }

    let mut client = connect()?;
    lookup_many(&mut client, &associations, secrets)
}

/// The part of [`read_from_keepassxc`] that talks to KeePassXC, separate so tests can
/// give it a client connected to a fake.
fn lookup_many(
    client: &mut Client,
    associations: &[Association],
    secrets: &[Secret],
) -> Result<Vec<String>> {
    // KeePassXC only answers a connection that has passed `test-associate`
    // against the active database, so the active one must be paired. The
    // search itself may cover more databases: all pairings are sent along, and
    // KeePassXC uses them for every open database if "search in all opened
    // databases" is on.
    active_association(client, associations)?.ok_or(
        "the active KeePassXC database is not paired with this machine. Switch to the right \
         database, or run `kgrant pair` for this one",
    )?;

    // One request per entry, in the order the entries first appear. An entry
    // that does not exist, and a field that is missing, are collected, so that
    // all of them can be fixed in one go; anything else stops at once.
    let mut problems: Vec<String> = Vec::new();
    let mut logins: Vec<(&str, Option<Login>)> = Vec::new();
    for secret in secrets {
        if !logins.iter().any(|(entry, _)| *entry == secret.entry) {
            let login = lookup_entry(client, associations, &secret.entry)?;
            if login.is_none() {
                problems.push(no_entry(&secret.entry));
            }
            logins.push((&secret.entry, login));
        }
    }

    let mut values = Vec::new();
    for secret in secrets {
        let (_, login) = logins
            .iter()
            .find(|(entry, _)| *entry == secret.entry)
            .expect("every entry was looked up");
        let Some(login) = login else { continue };
        match field_of(login, secret) {
            Ok(value) => values.push(value),
            Err(problem) => {
                if !problems.contains(&problem) {
                    problems.push(problem);
                }
            }
        }
    }

    match problems.len() {
        0 => Ok(values),
        1 => Err(problems.remove(0).into()),
        n => Err(format!(
            "{n} problems with the secrets:\n  - {}",
            problems.join("\n  - ")
        )
        .into()),
    }
}

fn no_entry(entry: &str) -> String {
    format!("no entry for `{entry}`: no entry in KeePassXC has the URL {URL_SCHEME}{entry}")
}

/// The one entry with the URL `kgrant://<entry>`, on a connection that has passed
/// `test-associate`.
fn lookup_entry(
    client: &mut Client,
    associations: &[Association],
    entry: &str,
) -> Result<Option<Login>> {
    let url = format!("{URL_SCHEME}{entry}");
    let mut logins = match client.get_logins(&url, associations) {
        Ok(logins) => logins,
        Err(e) if e.is_no_logins() => return Ok(None),
        Err(e) => return Err(explain(e)),
    };

    match logins.len() {
        // KeePassXC answers a denied request with an empty list, so this is
        // indistinguishable from an entry the client may not read.
        0 => Err(format!(
            "access to the entry `{entry}` was denied in KeePassXC (or it is not accessible)"
        )
        .into()),
        1 => Ok(Some(logins.remove(0))),
        n => {
            // Results come back in no particular order, so never pick one.
            let titles: Vec<_> = logins.iter().map(|l| l.name.as_str()).collect();
            Err(format!("{n} entries share the URL {url}: {}", titles.join(", ")).into())
        }
    }
}

/// The value of the field `KPH: <field>` of the entry.
fn field_of(login: &Login, secret: &Secret) -> std::result::Result<String, String> {
    if let Some(value) = login.field(&secret.field) {
        return Ok(value.to_owned());
    }
    let names = login.field_names();
    let title = &login.name;
    let (entry, field) = (&secret.entry, &secret.field);
    if names.is_empty() {
        Err(format!(
            "the entry `{title}` (kgrant://{entry}) has no field `{FIELD_PREFIX}{field}`, and \
             KeePassXC returned no `{FIELD_PREFIX}` fields of it at all. Add the field, and \
             check that \"Return also advanced string fields which start with 'KPH: '\" is \
             on in the browser-integration settings of KeePassXC"
        ))
    } else {
        Err(format!(
            "the entry `{title}` (kgrant://{entry}) has no field `{FIELD_PREFIX}{field}`. Its \
             `{FIELD_PREFIX}` fields are: {}",
            names.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::keepassxc::fake::{Fake, error_response, serve};
    use crate::secrets::testing::{
        answer_get_logins, answer_test_associate, association, entry, error_of, secret,
    };

    /// Runs `lookup_many` for `secrets` against a fake that runs `script`
    /// after the handshake.
    fn lookup_against(
        associations: &[Association],
        secrets: &[Secret],
        script: impl FnOnce(&mut Fake) + Send + 'static,
    ) -> Result<Vec<String>> {
        let (_dir, path, server) = serve(move |fake| {
            fake.handshake();
            script(fake);
        });
        let mut client = Client::connect(&path).unwrap();
        let result = lookup_many(&mut client, associations, secrets);
        server.join().unwrap();
        result
    }

    fn lookup_one(
        secret: Secret,
        script: impl FnOnce(&mut Fake) + Send + 'static,
    ) -> Result<String> {
        lookup_against(&[association("a", "k")], &[secret], script).map(|mut v| v.remove(0))
    }

    #[test]
    fn a_secret_is_the_field_of_the_entry_with_the_matching_url_and_not_its_password() {
        let result = lookup_one(secret("Multi-Field", "Token"), |fake| {
            answer_test_associate(fake, true);
            answer_get_logins(
                fake,
                "kgrant://multi-field",
                &[entry(
                    "Multi-Field",
                    &[("Token", "hunter2"), ("User", "alice")],
                )],
            );
        });
        assert_eq!(result.unwrap(), "hunter2");
    }

    #[test]
    fn fields_of_one_entry_come_with_one_request() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            answer_test_associate(fake, true);
            // One `get-logins` for three secrets of two entries, in an order that
            // alternates between them: the entry `aws` is asked for once.
            answer_get_logins(
                fake,
                "kgrant://aws",
                &[entry(
                    "AWS",
                    &[("access-key-id", "id"), ("secret-access-key", "key")],
                )],
            );
            answer_get_logins(
                fake,
                "kgrant://porkbun",
                &[entry("Porkbun", &[("api-key", "pk")])],
            );
        });
        let mut client = Client::connect(&path).unwrap();
        let values = lookup_many(
            &mut client,
            &[association("a", "k")],
            &[
                secret("aws", "access-key-id"),
                secret("porkbun", "api-key"),
                secret("aws", "secret-access-key"),
            ],
        )
        .unwrap();
        server.join().unwrap();
        // In the order asked, though the requests were grouped by entry.
        assert_eq!(values, ["id", "pk", "key"]);
    }

    #[test]
    fn everything_that_is_missing_is_reported_at_once() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            answer_test_associate(fake, true);
            // `two` has no entry and `three` lacks a field: both are asked
            // about and both are reported, with the one that works in between.
            fake.read_encrypted();
            fake.send(error_response("get-logins", "15", "No logins found"));
            answer_get_logins(fake, "kgrant://three", &[entry("Three", &[("other", "v")])]);
            answer_get_logins(fake, "kgrant://one", &[entry("One", &[("f", "v1")])]);
        });
        let mut client = Client::connect(&path).unwrap();
        let error = error_of(lookup_many(
            &mut client,
            &[association("a", "k")],
            &[
                secret("two", "f"),
                secret("three", "f"),
                secret("three", "g"),
                secret("one", "f"),
            ],
        ));
        server.join().unwrap();
        assert!(error.starts_with("3 problems with the secrets:"), "{error}");
        assert!(error.contains("no entry for `two`"), "{error}");
        assert!(error.contains("no field `KPH: f`"), "{error}");
        assert!(error.contains("no field `KPH: g`"), "{error}");
        assert!(!error.contains("`one`"), "{error}");
    }

    #[test]
    fn a_denied_entry_stops_at_once_and_does_not_ask_for_more() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            answer_test_associate(fake, true);
            answer_get_logins(fake, "kgrant://one", &[]);
            // Nothing else is requested.
        });
        let mut client = Client::connect(&path).unwrap();
        let error = error_of(lookup_many(
            &mut client,
            &[association("a", "k")],
            &[secret("one", "f"), secret("two", "f")],
        ));
        server.join().unwrap();
        assert!(error.contains("denied"), "{error}");
    }

    #[test]
    fn lookup_tries_each_pairing_and_sends_all_of_them() {
        let associations = [association("a", "k1"), association("b", "k2")];
        let result = lookup_against(&associations, &[secret("default", "f")], |fake| {
            // The first pairing belongs to a database that is not active.
            answer_test_associate(fake, false);
            answer_test_associate(fake, true);
            let (nonce, request) = fake.read_encrypted();
            assert_eq!(request["keys"].as_array().unwrap().len(), 2);
            fake.reply(
                "get-logins",
                &nonce,
                json!({ "entries": [entry("Default", &[("f", "pw")])], "success": "true" }),
            );
        });
        assert_eq!(result.unwrap(), ["pw"]);
    }

    #[test]
    fn lookup_fails_when_the_active_database_is_not_paired() {
        let associations = [association("a", "k1"), association("b", "k2")];
        let result = lookup_against(&associations, &[secret("default", "f")], |fake| {
            answer_test_associate(fake, false);
            answer_test_associate(fake, false);
        });
        let error = error_of(result);
        assert!(error.contains("not paired with this machine"), "{error}");
    }

    #[test]
    fn lookup_says_when_keepassxc_is_locked() {
        let result = lookup_one(secret("default", "f"), |fake| {
            fake.read_encrypted();
            fake.send(error_response("test-associate", "1", "Database not opened"));
        });
        assert!(error_of(result).contains("locked"));
    }

    #[test]
    fn lookup_reports_an_unknown_entry_with_the_url_it_looked_for() {
        let result = lookup_one(secret("Not There", "f"), |fake| {
            answer_test_associate(fake, true);
            fake.read_encrypted();
            fake.send(error_response("get-logins", "15", "No logins found"));
        });
        assert_eq!(
            error_of(result),
            "no entry for `not-there`: no entry in KeePassXC has the URL kgrant://not-there"
        );
    }

    #[test]
    fn lookup_reports_a_denied_request() {
        let result = lookup_one(secret("default", "f"), |fake| {
            answer_test_associate(fake, true);
            answer_get_logins(fake, "kgrant://default", &[]);
        });
        let error = error_of(result);
        assert!(error.contains("denied"), "{error}");
    }

    #[test]
    fn lookup_never_picks_between_entries_sharing_a_url() {
        let result = lookup_one(secret("default", "f"), |fake| {
            answer_test_associate(fake, true);
            answer_get_logins(
                fake,
                "kgrant://default",
                &[
                    entry("First", &[("f", "value-first")]),
                    entry("Second", &[("f", "value-second")]),
                ],
            );
        });
        let error = error_of(result);
        assert!(
            error.contains("2 entries share the URL kgrant://default"),
            "{error}"
        );
        assert!(
            error.contains("First") && error.contains("Second"),
            "{error}"
        );
        // The error names the entries but must not leak their values.
        assert!(!error.contains("value-"), "{error}");
    }

    #[test]
    fn a_missing_field_names_the_fields_the_entry_has() {
        let result = lookup_one(secret("aws", "nope"), |fake| {
            answer_test_associate(fake, true);
            answer_get_logins(
                fake,
                "kgrant://aws",
                &[entry("AWS", &[("access-key-id", "id"), ("secret", "s")])],
            );
        });
        let error = error_of(result);
        assert!(error.contains("no field `KPH: nope`"), "{error}");
        assert!(error.contains("access-key-id, secret"), "{error}");
        assert!(!error.contains("decoy-password"), "{error}");
    }

    #[test]
    fn an_entry_without_any_returned_fields_points_at_the_setting_and_never_at_the_password() {
        let result = lookup_one(secret("aws", "access-key-id"), |fake| {
            answer_test_associate(fake, true);
            answer_get_logins(fake, "kgrant://aws", &[entry("AWS", &[])]);
        });
        let error = error_of(result);
        assert!(error.contains("no field `KPH: access-key-id`"), "{error}");
        assert!(
            error.contains("Return also advanced string fields"),
            "{error}"
        );
        assert!(!error.contains("decoy-password"), "{error}");
    }

    #[test]
    fn lookup_passes_other_keepassxc_errors_on() {
        let result = lookup_one(secret("default", "f"), |fake| {
            answer_test_associate(fake, true);
            fake.read_encrypted();
            fake.send(error_response("get-logins", "5", "Something else"));
        });
        assert_eq!(
            error_of(result),
            "KeePassXC returned error 5: Something else"
        );
    }
}
