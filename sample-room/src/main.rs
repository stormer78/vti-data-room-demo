//! The demo's **sample room** — local stand-in infrastructure, not part of the site.
//!
//! It exists so the demo runs standalone. In a real deployment neither half of this is
//! here: the host is a VTC or the standalone `room-host` binary, and the owner is a person
//! with a VTA driving it from the wallet console or `pnm-cli`. The site in `../web` does
//! not know the difference, and the moment it needs to, the demo has stopped demonstrating
//! anything.
//!
//! The two parts it plays:
//!
//! - the room's **owner**, who admits people. Admission has to invert for a browser: the
//!   published ceremony has the owner call `rooms/keys/key-package` *on the member's VTA*
//!   and push a Welcome to it, and a tab has no DIDComm address and no inbox. So the
//!   browser mints its KeyPackage locally and **pulls** the Welcome from `POST /api/join`.
//! - the room's **host**, who stores what members write. It stores ciphertext and cannot
//!   read a byte of it — that is not a demo shortcut, it is the property being shown, and
//!   the `/api/records` handlers below have no way to decrypt even if they wanted to.
//!
//! Everything else the site does — holding the group, sealing, opening, walking the epoch
//! chain — happens in the browser, in the same `vti-rooms` this binary links, compiled to
//! wasm.
//!
//! # What this deliberately is not
//!
//! Not a VTA, and not a VTC. A real room's admission issues credentials the *room* signs
//! (`rooms/owner/{invite,issue-membership,issue-authority}`) and a real host authorises
//! every operation against a presentation minted from them. This admits anyone who asks
//! and authorises nothing, which is why it says so on screen. The record path is real; the
//! authority path is the next slice.

mod owner;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use vti_rooms::mls::RoomGroup;

use crate::owner::RoomIdentity;

/// One demo room: its group, and the ciphertext its members have stored.
struct Room {
    /// The room's identifier. A real room mints a `did:webvh` before it tells any host;
    /// this one is a fixed string, because a demo room that could not be linked to is a
    /// demo nobody can open twice.
    id: String,
    /// A human name for the catalogue.
    label: String,
    /// The room's own signing identity. A room issues the credentials that govern it, so
    /// it needs a key of its own — see [`crate::owner`].
    identity: RoomIdentity,
    /// The owner's own credentials for this room, so it can act as a member with `admin`.
    ///
    /// Minting an epoch at the host is a room operation like any other: it takes a
    /// presentation, and the room has to have granted the owner the authority to make one.
    /// A room whose owner could act without a credential would be a room with a back door.
    owner_membership: String,
    owner_authority: String,
    /// Invitations already spent, by credential id.
    ///
    /// The owner's half of single-use. The member enforces it too, in their own browser,
    /// and neither substitutes for the other: the member's copy stops *their* key holder
    /// being filled twice, this one stops a replayed invitation adding a second leaf.
    spent_invitations: Vec<String>,
    /// The owner's MLS group. Every admission commits, which advances the epoch — which is
    /// why members must apply commits or lose the ability to open anything newer.
    group: RoomGroup,
    /// `key` → the record. Opaque: `sealed` is base64 ciphertext under a key this process
    /// never holds.
    records: BTreeMap<String, Record>,
    /// Monotonic **per room**, not per record — one comparable number is what an
    /// incremental-sync watermark needs, and per-record counters are not comparable to
    /// each other.
    next_version: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    key: String,
    version: u64,
    /// The sealed content, exactly as the member's browser produced it.
    sealed: serde_json::Value,
    /// Who wrote it. Visible because this is an `attributed` room: the host learns *that* a
    /// member acted, never *what* they wrote.
    author: String,
}

/// Everything the sample holds: the rooms, the owner that governs them, and where their
/// host is. One state rather than three globals, because the owner and the host URL are
/// needed by the same handlers that touch a room.
struct Demo {
    owner: RoomIdentity,
    host_url: String,
    rooms: Mutex<BTreeMap<String, Room>>,
}

type Rooms = Arc<Demo>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CatalogueEntry {
    room_id: String,
    /// The room's DID — what a member verifies its credentials against, recovered
    /// lexically because it is a `did:key`.
    room_did: String,
    label: String,
    epoch: u32,
    members: usize,
}

async fn catalogue(State(rooms): State<Rooms>) -> Json<Vec<CatalogueEntry>> {
    let rooms = rooms.rooms.lock().await;
    Json(
        rooms
            .values()
            .map(|r| CatalogueEntry {
                room_id: r.id.clone(),
                room_did: r.identity.did.clone(),
                label: r.label.clone(),
                epoch: (r.group.epoch() + 1) as u32,
                members: r.group.member_count(),
            })
            .collect(),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteRequest {
    /// The DID to admit. Told to the owner out of band — which is the point: admission is
    /// a decision somebody makes about somebody, not a form a stranger fills in.
    did: String,
}

/// Issue an invitation.
///
/// A demo room admits anyone who asks, and says so on screen. What is *not* faked is the
/// artefact: this is a real DTG credential, signed by the room, naming one subject, valid
/// for an hour, single-use. A real owner decides whether to call this; the ceremony either
/// side of it is identical.
async fn invite(
    State(rooms): State<Rooms>,
    Path(room_id): Path<String>,
    Json(req): Json<InviteRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let rooms = rooms.rooms.lock().await;
    let room = rooms
        .get(&room_id)
        .ok_or((StatusCode::NOT_FOUND, format!("no room `{room_id}`")))?;

    let invitation = room
        .identity
        .invite(&req.did)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(serde_json::json!({
        "invitation": serde_json::from_str::<serde_json::Value>(&invitation)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        "roomDid": room.identity.did,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinRequest {
    /// The visitor's own `did:key`, minted in their browser.
    did: String,
    /// Their KeyPackage, base64url — the public half of an identity they keep privately.
    key_package: String,
    /// The invitation this room issued them.
    invitation: serde_json::Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinResponse {
    room_id: String,
    /// The Welcome, base64url. Sealed to the KeyPackage above and to nothing else.
    welcome: String,
    /// The room's epoch after the commit this admission produced.
    epoch: u32,
    /// The room's attestation that this DID belongs to it.
    membership: serde_json::Value,
    /// What this member may do — the chain root they attenuate from, per request.
    authority: serde_json::Value,
    /// Each step the owner took, so the site can show the ceremony rather than a spinner.
    steps: Vec<String>,
}

/// Admit anyone who asks — see the module docs on why that is stated rather than hidden.
async fn join(
    State(demo): State<Rooms>,
    Path(room_id): Path<String>,
    Json(req): Json<JoinRequest>,
) -> Result<Json<JoinResponse>, (StatusCode, String)> {
    let (owner, host_url) = (&demo.owner, demo.host_url.clone());
    let mut rooms = demo.rooms.lock().await;
    let room = rooms
        .get_mut(&room_id)
        .ok_or((StatusCode::NOT_FOUND, format!("no room `{room_id}`")))?;

    // The owner's half of the two-party check. The member checked this invitation too,
    // in their own browser, and neither substitutes for the other: theirs stops their key
    // holder being filled with a room they never agreed to join; this one stops a replayed
    // or forged invitation adding a leaf to the group.
    let invitation: dtg_credentials::DTGCredential =
        serde_json::from_value(req.invitation.clone())
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("invitation: {e}")))?;
    let credential_id = invitation
        .id()
        .ok_or((
            StatusCode::BAD_REQUEST,
            "the invitation carries no id, so single use cannot be enforced".to_string(),
        ))?
        .to_string();

    if invitation.issuer() != room.identity.did {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "that invitation was issued by `{}`, not by this room",
                invitation.issuer()
            ),
        ));
    }
    if invitation.subject() != req.did {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "that invitation names `{}`, not you — an invitation is not transferable",
                invitation.subject()
            ),
        ));
    }
    // Against the room's own key, recovered from its own identifier. Nothing to resolve.
    let (_, room_key) = multibase::decode(&room.identity.did["did:key:".len()..])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("room did: {e}")))?;
    invitation
        .verify_proof_with_public_key(&room_key[2..])
        .map_err(|_| {
            (
                StatusCode::FORBIDDEN,
                "that invitation's proof does not verify against this room's key".to_string(),
            )
        })?;
    if room.spent_invitations.contains(&credential_id) {
        return Err((
            StatusCode::CONFLICT,
            format!("invitation `{credential_id}` has already been used"),
        ));
    }

    let key_package = B64
        .decode(req.key_package.as_bytes())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("key package: {e}")))?;

    let change = room
        .group
        .add_member_from_bytes(&key_package)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("add member: {e}")))?;

    // A removal produces no Welcome; an addition always does. If this is ever `None` the
    // member would join a group nobody added them to, which fails at the first read looking
    // like a bad Welcome rather than a wrong identity — so it is an error here instead.
    let welcome = change.welcome.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "adding a member produced no Welcome".to_string(),
    ))?;

    // Consumed only now, after the join succeeded. Spending it earlier would burn an
    // invitation on a failed attempt and leave the member unable to retry.
    room.spent_invitations.push(credential_id);

    // Membership and authority are separate acts because they are separate facts: being a
    // member is not being allowed to write. A demo visitor gets `read` and `write` and not
    // `curate` or `admin`, so the room has a governance surface rather than one bit.
    let membership = room
        .identity
        .issue_membership(&req.did)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let authority = room
        .identity
        .issue_authority(&req.did, &["read", "write"])
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let epoch = (change.epoch + 1) as u32;

    // The commit advanced the epoch, so the host has to be told before the new member can
    // write anything: a record is sealed under the epoch current when it was written, and
    // a host refuses ciphertext bound to an epoch it does not know about.
    if let Err(e) = mint_epoch(&host_url, &owner, room, epoch).await {
        return Err((StatusCode::BAD_GATEWAY, e));
    }

    Ok(Json(JoinResponse {
        room_id,
        welcome: B64.encode(welcome),
        epoch,
        membership: serde_json::from_str(&membership)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        authority: serde_json::from_str(&authority)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        steps: vec![
            "invitation verified — issued by this room, to you, unspent".into(),
            "key package validated against the room's ciphersuite".into(),
            format!("member added — the group committed to epoch {epoch}"),
            "welcome sealed to that key package alone".into(),
            "membership credential issued".into(),
            "authority credential issued — read, write".into(),
        ],
    }))
}

async fn list_records(
    State(rooms): State<Rooms>,
    Path(room_id): Path<String>,
) -> Result<Json<Vec<Record>>, (StatusCode, String)> {
    let rooms = rooms.rooms.lock().await;
    let room = rooms
        .get(&room_id)
        .ok_or((StatusCode::NOT_FOUND, format!("no room `{room_id}`")))?;
    Ok(Json(room.records.values().cloned().collect()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutRecord {
    /// The sealed content the member's browser produced. The version bound *inside* it must
    /// be the version this store assigns, or the record stores fine and never opens — which
    /// is why the browser asks for the version first and seals against the answer.
    sealed: serde_json::Value,
    expected_version: u64,
    author: String,
}

async fn put_record(
    State(rooms): State<Rooms>,
    Path((room_id, key)): Path<(String, String)>,
    Json(req): Json<PutRecord>,
) -> Result<Json<Record>, (StatusCode, String)> {
    let mut rooms = rooms.rooms.lock().await;
    let room = rooms
        .get_mut(&room_id)
        .ok_or((StatusCode::NOT_FOUND, format!("no room `{room_id}`")))?;

    if req.expected_version != room.next_version {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "this write sealed itself for version {} but the room is at {}. Re-read and \
                 seal again — the version is bound into the ciphertext, so a record stored \
                 under the wrong one would never open.",
                req.expected_version, room.next_version
            ),
        ));
    }

    let record = Record {
        key: key.clone(),
        version: room.next_version,
        sealed: req.sealed,
        author: req.author,
    };
    room.next_version += 1;
    room.records.insert(key, record.clone());
    Ok(Json(record))
}

/// The version a write should seal itself for.
async fn next_version(
    State(rooms): State<Rooms>,
    Path(room_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let rooms = rooms.rooms.lock().await;
    let room = rooms
        .get(&room_id)
        .ok_or((StatusCode::NOT_FOUND, format!("no room `{room_id}`")))?;
    Ok(Json(serde_json::json!({ "nextVersion": room.next_version })))
}

/// Tell the host the room's epoch advanced.
///
/// Every membership change is a commit and every commit advances the epoch, and a record
/// is sealed under the epoch current when it was written. A host that has not been told
/// refuses the write — "record is sealed under epoch 2, room is at 1" — which is the host
/// being right: it is the party that knows what version a record will be stored at, and it
/// cannot accept ciphertext bound to an epoch it has never heard of.
///
/// Needs `admin`, which is why the room issues its owner credentials of its own.
///
/// No `link` yet: this sample drives `RoomGroup` directly rather than `SealedRoom`, so it
/// never mints a rung, and the room's history is readable only from where a member joined.
/// That is the honest `FromJoin` behaviour and the site shows it — `earliest readable`
/// equal to `your epoch` is exactly this and not a bug.
async fn mint_epoch(
    host_url: &str,
    owner: &RoomIdentity,
    room: &Room,
    epoch: u32,
) -> Result<(), String> {
    let presentation = owner
        .present(&room.owner_authority, &room.owner_membership, "admin")
        .await?;
    let document = serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/rooms/epoch/mint/0.1",
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": { "roomId": room.identity.did, "epoch": epoch, "presentation": presentation },
    });
    let signed = owner.sign_document(document).await?;

    let res = reqwest::Client::new()
        .post(format!("{host_url}/trust-tasks"))
        .json(&signed)
        .send()
        .await
        .map_err(|e| format!("reach the host: {e}"))?;
    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("the host refused the epoch mint ({status}): {body}"));
    }
    Ok(())
}

/// Register a room with its host.
///
/// The order is forced and it is the whole reason a room has an identity of its own: the
/// DID is minted first, and a host is then *told about* a room that already exists. A host
/// that named the room would be a host the room could never leave — "a room identified by
/// something its host chose could not move to another host".
///
/// Signed as the owner, not as the room. A registration is a request to store something,
/// authorised against the party asking; signing as the room would claim the room is asking
/// to be stored, which is neither true nor something the host can check.
async fn register_with_host(
    host_url: &str,
    owner: &RoomIdentity,
    room_did: &str,
) -> Result<(), String> {
    let document = serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/rooms/create/0.1",
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": {
            "roomId": room_did,
            // `attributed`: the host stores ciphertext it cannot read, and learns which
            // member acted. `open` would defeat the demonstration; `private` needs a
            // zero-knowledge subject binding the working group has not settled, and a tier
            // that quietly behaved like this one would misrepresent it.
            "visibility": "attributed",
            "ownerDid": owner.did,
        },
    });
    let signed = owner.sign_document(document).await?;

    let res = reqwest::Client::new()
        .post(format!("{host_url}/trust-tasks"))
        .json(&signed)
        .send()
        .await
        .map_err(|e| format!("reach the host at {host_url}: {e}"))?;

    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    if !status.is_success() {
        // A host's `trust-task-error` is its ANSWER, not a broken network. Surfacing the
        // body is the difference between "the host refused, and here is why" and a number.
        return Err(format!("the host refused to register the room ({status}): {body}"));
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    let host_url = std::env::var("ROOM_HOST_URL").unwrap_or_else(|_| "http://127.0.0.1:8300".into());

    // One owner for the whole sample. In a real deployment this is a person with a VTA;
    // the rooms' keys are held by them, which is exactly how `RoomKeySigner` works
    // server-side — a room signs, but its key lives in its owner's agent.
    let owner = RoomIdentity::mint().expect("mint the owner's identity");
    println!("owner: {}", owner.did);

    let mut rooms = BTreeMap::new();
    for (id, label) in [
        ("demo-library", "The Library — a shared reading room"),
        ("demo-workshop", "The Workshop — notes an agent can recall"),
    ] {
        // Identity first, then the group. A room is a DTG node before it is a set of keys,
        // and the order is forced: a host told about a room it named could never let it
        // leave.
        let identity = RoomIdentity::mint().expect("mint the room's identity");
        let group = RoomGroup::create(&identity.did).expect("create the demo room group");
        // The room grants its owner everything, including `admin` — which is what lets the
        // owner mint an epoch at the host. Issued by the room, like every other authority
        // in it: an owner acting without a credential would be a back door.
        let owner_membership = identity
            .issue_membership(&owner.did)
            .await
            .expect("issue the owner's membership");
        let owner_authority = identity
            .issue_authority(&owner.did, &["read", "write", "curate", "admin"])
            .await
            .expect("issue the owner's authority");

        match register_with_host(&host_url, &owner, &identity.did).await {
            Ok(()) => println!("registered {id} ({}) with {host_url}", identity.did),
            Err(e) => {
                // Not fatal: the demo is still worth running against the sample's own
                // record API, and a host that is not up yet is the common case when
                // somebody starts one process and not the other. Say which, plainly.
                eprintln!("warning: {id} is not registered with a host — {e}");
                eprintln!("         start `room-host --allow-origin http://127.0.0.1:8787` and restart this.");
            }
        }

        rooms.insert(
            id.to_string(),
            Room {
                id: id.to_string(),
                label: label.to_string(),
                identity,
                owner_membership,
                owner_authority,
                spent_invitations: Vec::new(),
                group,
                records: BTreeMap::new(),
                next_version: 1,
            },
        );
    }
    let rooms: Rooms = Arc::new(Demo {
        owner,
        host_url,
        rooms: Mutex::new(rooms),
    });

    let web = std::env::var("DEMO_WEB_DIR").unwrap_or_else(|_| "../web".to_string());
    let app = Router::new()
        .route("/api/rooms", get(catalogue))
        .route("/api/rooms/{room_id}/invite", post(invite))
        .route("/api/rooms/{room_id}/join", post(join))
        .route("/api/rooms/{room_id}/next-version", get(next_version))
        .route(
            "/api/rooms/{room_id}/records",
            get(list_records),
        )
        .route("/api/rooms/{room_id}/records/{key}", axum::routing::put(put_record))
        .layer(tower_http::cors::CorsLayer::permissive())
        .fallback_service(tower_http::services::ServeDir::new(&web))
        .with_state(rooms);

    let addr = "127.0.0.1:8787";
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind the demo port");
    println!("data-room demo on http://{addr}  (serving {web})");
    axum::serve(listener, app).await.expect("serve");
}
