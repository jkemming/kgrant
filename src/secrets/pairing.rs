use std::path::Path;

use crate::keepassxc::Client;
use crate::{Result, store};

use super::connection::{active_association, connect, explain};

pub fn pair() -> Result<()> {
    let path = store::association_path()?;
    let mut client = connect()?;
    pair_with(&mut client, &path)
}

fn pair_with(client: &mut Client, path: &Path) -> Result<()> {
    if let Some(existing) = active_association(client, &store::load(path)?)? {
        return Err(format!(
            "the active KeePassXC database is already paired (as `{}`)",
            existing.id
        )
        .into());
    }

    eprintln!("Approve the pairing dialog in KeePassXC.");
    let association = client.associate().map_err(explain)?;
    let id = association.id.clone();
    store::add(path, association)?;
    eprintln!("Paired as `{}`. Saved to {}", id, path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::keepassxc::fake::{Fake, serve};
    use crate::secrets::testing::{answer_test_associate, association};

    fn pair_against(path: &Path, script: impl FnOnce(&mut Fake) + Send + 'static) -> Result<()> {
        let (_dir, socket, server) = serve(move |fake| {
            fake.handshake();
            script(fake);
        });
        let mut client = Client::connect(&socket).unwrap();
        let result = pair_with(&mut client, path);
        server.join().unwrap();
        result
    }

    fn answer_associate(fake: &mut Fake, id: &str) {
        let (nonce, request) = fake.read_encrypted();
        assert_eq!(request["action"], "associate");
        fake.reply("associate", &nonce, json!({ "id": id, "success": "true" }));
    }

    fn stored_ids(path: &Path) -> Vec<String> {
        store::load(path)
            .unwrap()
            .into_iter()
            .map(|a| a.id)
            .collect()
    }

    #[test]
    fn pairing_saves_the_new_association() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("association.json");
        pair_against(&path, |fake| answer_associate(fake, "new")).unwrap();
        assert_eq!(stored_ids(&path), ["new"]);
    }

    #[test]
    fn pairing_refuses_a_database_that_is_already_paired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("association.json");
        store::add(&path, association("old", "k")).unwrap();
        let result = pair_against(&path, |fake| answer_test_associate(fake, true));
        assert_eq!(
            result.unwrap_err().to_string(),
            "the active KeePassXC database is already paired (as `old`)"
        );
        assert_eq!(stored_ids(&path), ["old"]);
    }

    #[test]
    fn pairing_a_second_database_keeps_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("association.json");
        store::add(&path, association("other", "k")).unwrap();
        pair_against(&path, |fake| {
            answer_test_associate(fake, false);
            answer_associate(fake, "new");
        })
        .unwrap();
        assert_eq!(stored_ids(&path), ["other", "new"]);
    }
}
