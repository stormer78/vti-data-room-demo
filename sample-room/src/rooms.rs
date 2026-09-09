//! Which rooms this owner offers, and what each one grants.
//!
//! Read from a file rather than compiled in, because "set up a room" should be something a
//! person does rather than something they edit Rust to do. The site was always able to work
//! against any room by DID; this is the sample owner catching up with it.
//!
//! # A room is defined by what it grants
//!
//! Not by a name, and not by a label. `grants` is the authority the room confers on somebody
//! it admits, and it is the whole of what makes two rooms different here — the same button is
//! offered in every room and only works where the room conferred the action. A demo where
//! every room granted everything would be demonstrating storage.

use serde::Deserialize;

/// One room this owner offers.
#[derive(Clone, Debug, Deserialize)]
pub struct RoomSpec {
    /// A short slug, for the catalogue. **Not** the room's identifier — that is the DID it
    /// mints at startup, and it is what everything in the trust model means by "room".
    pub id: String,
    /// A human name for the catalogue.
    pub label: String,
    /// What this room confers on a member it admits.
    pub grants: Vec<String>,
}

/// The actions a host understands.
///
/// Checked at load, because a typo here would otherwise become a credential granting
/// something nothing recognises — and it would fail at the first attempt to *use* it, in a
/// browser, as a refusal from `attenuate` about an action the room never conferred. Which is
/// true, and unhelpful, and a long way from the line that caused it.
const KNOWN: [&str; 4] = ["read", "write", "curate", "admin"];

/// The rooms this demo ships with, when nothing else is named.
///
/// Two, and they differ only in `curate`, because one room is not enough to show that
/// authority is a property of the grant rather than of the screen.
fn built_in() -> Vec<RoomSpec> {
    vec![
        RoomSpec {
            id: "demo-library".into(),
            label: "The Library — a shared reading room".into(),
            grants: vec!["read".into(), "write".into()],
        },
        RoomSpec {
            id: "demo-workshop".into(),
            label: "The Workshop — notes an agent can recall".into(),
            grants: vec!["read".into(), "write".into(), "curate".into()],
        },
    ]
}

/// Load the rooms named by `path`, or the built-in pair when there is none.
///
/// A missing file is the default rather than an error: running the demo with no arguments
/// should show you a room. A file that is *named* and unreadable is an error, because
/// somebody who said `ROOMS_FILE=…` meant it.
pub fn load(path: Option<&str>) -> Result<Vec<RoomSpec>, String> {
    let Some(path) = path else {
        return Ok(built_in());
    };

    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read the rooms file `{path}`: {e}"))?;
    let rooms: Vec<RoomSpec> =
        serde_json::from_str(&text).map_err(|e| format!("`{path}` is not a list of rooms: {e}"))?;

    if rooms.is_empty() {
        return Err(format!(
            "`{path}` names no rooms, so there would be nothing to join"
        ));
    }
    for room in &rooms {
        if room.grants.is_empty() {
            return Err(format!(
                "room `{}` grants nothing, so a member admitted to it could not even read",
                room.id
            ));
        }
        for grant in &room.grants {
            if !KNOWN.contains(&grant.as_str()) {
                return Err(format!(
                    "room `{}` grants `{grant}`, which no host understands — the actions are \
                     {}. A credential conferring it would be issued happily and refused at \
                     first use, which is a long way from here.",
                    room.id,
                    KNOWN.join(", ")
                ));
            }
        }
    }

    // Two rooms with one slug would give the catalogue two entries that look alike and
    // behave differently, and only one of them would ever be found by `id`.
    let mut seen = std::collections::BTreeSet::new();
    for room in &rooms {
        if !seen.insert(&room.id) {
            return Err(format!("`{path}` names room `{}` twice", room.id));
        }
    }

    Ok(rooms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(json: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f
    }

    #[test]
    fn no_file_means_the_built_in_pair() {
        let rooms = load(None).unwrap();
        assert_eq!(rooms.len(), 2);
        // The pair differs by `curate` and that difference is the demonstration, so it is
        // asserted rather than left to whoever edits the list next.
        assert!(
            rooms
                .iter()
                .any(|r| r.grants.contains(&"curate".to_string()))
        );
        assert!(
            rooms
                .iter()
                .any(|r| !r.grants.contains(&"curate".to_string()))
        );
    }

    #[test]
    fn a_named_file_replaces_them() {
        let f = write(r#"[{"id":"mine","label":"Mine","grants":["read"]}]"#);
        let rooms = load(Some(f.path().to_str().unwrap())).unwrap();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0].id, "mine");
        assert_eq!(rooms[0].grants, vec!["read"]);
    }

    /// A grant no host understands is caught here, not at first use.
    #[test]
    fn an_unknown_grant_is_refused_with_the_list() {
        let f = write(r#"[{"id":"a","label":"A","grants":["read","delete"]}]"#);
        let err = load(Some(f.path().to_str().unwrap())).unwrap_err();
        assert!(err.contains("`delete`"), "{err}");
        assert!(err.contains("read, write, curate, admin"), "{err}");
    }

    #[test]
    fn a_room_that_grants_nothing_is_refused() {
        let f = write(r#"[{"id":"a","label":"A","grants":[]}]"#);
        assert!(
            load(Some(f.path().to_str().unwrap()))
                .unwrap_err()
                .contains("grants nothing")
        );
    }

    #[test]
    fn an_empty_list_is_refused() {
        let f = write("[]");
        assert!(
            load(Some(f.path().to_str().unwrap()))
                .unwrap_err()
                .contains("no rooms")
        );
    }

    #[test]
    fn a_duplicated_slug_is_refused() {
        let f = write(
            r#"[{"id":"a","label":"A","grants":["read"]},{"id":"a","label":"B","grants":["read"]}]"#,
        );
        assert!(
            load(Some(f.path().to_str().unwrap()))
                .unwrap_err()
                .contains("twice")
        );
    }

    /// A file that was *named* and cannot be read is an error, where an unnamed one is not.
    #[test]
    fn a_named_but_missing_file_is_an_error() {
        assert!(
            load(Some("/nonexistent/rooms.json"))
                .unwrap_err()
                .contains("could not read")
        );
    }
}
