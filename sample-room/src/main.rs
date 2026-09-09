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

mod admission;
mod mediator;
mod owner;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use vti_rooms::mls::RoomGroup;
use vti_rooms::sealed::SealedRoom;
use vti_rooms::wire::EpochLink;

use crate::owner::RoomIdentity;

/// One demo room: its group, and the ciphertext its members have stored.
pub(crate) struct Room {
    /// The room's identifier. A real room mints a `did:webvh` before it tells any host;
    /// this one is a fixed string, because a demo room that could not be linked to is a
    /// demo nobody can open twice.
    pub(crate) id: String,
    /// A human name for the catalogue.
    pub(crate) label: String,
    /// The room's own signing identity. A room issues the credentials that govern it, so
    /// it needs a key of its own — see [`crate::owner`].
    pub(crate) identity: RoomIdentity,
    /// What this room grants a member it admits.
    ///
    /// Different per room on purpose. Authorization is a property of the grant, not of the
    /// screen: the same button is offered in both rooms and only works in one, because only
    /// one room's owner conferred the action. A demo where every member could do everything
    /// would be demonstrating storage.
    pub(crate) member_actions: &'static [&'static str],
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
    pub(crate) spent_invitations: Vec<String>,
    /// Every commit this room has made, in order, from epoch 2 onwards.
    ///
    /// **The piece the published ceremony does not have.** Every membership change is a
    /// commit and every commit advances the epoch; a member who misses one is stuck at
    /// their last epoch and can open nothing sealed after it. The symptom is "this record
    /// does not open", which reads like corruption rather than like a message that never
    /// arrived.
    ///
    /// In the real design a commit reaches a member's agent over DIDComm, pushed. A browser
    /// has no inbox, so it has to **pull** — the same inversion the invitation forced — and
    /// something has to keep the commits for it to pull. That is this.
    ///
    /// Public, and safe to be: a commit is MLS handshake material that authenticates its
    /// committer *inside the group*. It confers nothing on a non-member, and a member who
    /// is entitled to the room is entitled to its history of membership changes.
    pub(crate) commits: Vec<CommittedEpoch>,
    /// The room's group **and its epoch key chain**.
    ///
    /// `SealedRoom` rather than a bare `RoomGroup`, and that is the whole of what makes a
    /// room's history readable. Every admission commits and every commit advances the
    /// epoch; sealing the outgoing epoch's key under the incoming one — a *rung* — is what
    /// lets a member who arrives at epoch 5 walk back and read epoch 2. A `RoomGroup` alone
    /// mints no rungs, so every member could read only from where they joined.
    ///
    /// The walk is backwards only, which is what keeps removal forward-only: a rung lets
    /// you go down from a key you hold, never up to one you do not.
    pub(crate) room: SealedRoom,
    /// `key` → the record. Opaque: `sealed` is base64 ciphertext under a key this process
    /// never holds.
    records: BTreeMap<String, Record>,
    /// Monotonic **per room**, not per record — one comparable number is what an
    /// incremental-sync watermark needs, and per-record counters are not comparable to
    /// each other.
    next_version: u64,
}

/// One commit and the epoch it produced.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommittedEpoch {
    /// The epoch the group is at *after* applying this. A member at `epoch - 1` needs it.
    pub(crate) epoch: u32,
    /// The commit, base64url.
    pub(crate) commit: String,
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
pub(crate) struct Demo {
    pub(crate) owner: RoomIdentity,
    pub(crate) host_url: String,
    /// The address this sample hands **members** for its host.
    ///
    /// Not the same field as `host_url`, and the difference is the point rather than an
    /// inconsistency. The owner is a server: it can open a URL, so it does. A browser often
    /// cannot — the host may be behind NAT, on a laptop, or on an origin no page is permitted
    /// to call — so it is given the host's DID and reaches it through a mediator instead.
    ///
    /// One host, serving both at once, and the client picks. That is the shape a real
    /// deployment has, and collapsing the two fields would hide it.
    pub(crate) member_host: String,
    pub(crate) rooms: Mutex<BTreeMap<String, Room>>,
}

type Rooms = Arc<Demo>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CatalogueEntry {
    room_id: String,
    /// Where this room's records live, as an address a member can act on.
    ///
    /// A URL or a **host DID**, and the site does the same thing with either — signs a Trust
    /// Task and sends it. Which one it is decides only the carrier.
    ///
    /// Carried here rather than assumed, because a room's identifier deliberately does not
    /// name its host: a room may be served by several, and one that named its host could
    /// never move. So somebody has to say, and for a listed room that is the catalogue.
    host: String,
    /// What this room grants a member. Shown before joining, because it is the difference
    /// between the two rooms and the whole of what the demo is about.
    grants: Vec<String>,
    /// The room's DID — what a member verifies its credentials against, recovered
    /// lexically because it is a `did:key`.
    room_did: String,
    label: String,
    epoch: u32,
    members: usize,
}

async fn catalogue(State(demo): State<Rooms>) -> Json<Vec<CatalogueEntry>> {
    let host = demo.member_host.clone();
    let rooms = demo;
    let rooms = rooms.rooms.lock().await;
    Json(
        rooms
            .values()
            .map(|r| CatalogueEntry {
                room_id: r.id.clone(),
                host: host.clone(),
                grants: r.member_actions.iter().map(|a| (*a).to_string()).collect(),
                room_did: r.identity.did.clone(),
                label: r.label.clone(),
                epoch: r.room.room_epoch(),
                members: r.room.group().member_count(),
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

/// Issue an invitation, over HTTP.
///
/// **The weaker of the two carriers, and deliberately the one for the sample's own
/// catalogue.** It takes the asker's DID as a *claim*: there is no transport identity to
/// check it against, so anybody who can reach this port can have an invitation minted naming
/// anybody. That is fine for a local demo whose rooms admit all comers, and it is not the
/// path a stranger uses — [`crate::mediator`] is, and there the request carries a proof of
/// the room key and a binding to the connection it arrived on.
///
/// Both call the same [`crate::admission::issue_invitation`], so the credential is identical
/// and neither carrier holds a rule the other does not.
async fn invite(
    State(demo): State<Rooms>,
    Path(room_id): Path<String>,
    Json(req): Json<InviteRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // The catalogue addresses rooms by slug; admission addresses them by DID, because that
    // is all a member has. Translate here rather than teaching admission about slugs.
    let room_did = {
        let rooms = demo.rooms.lock().await;
        rooms
            .get(&room_id)
            .map(|r| r.identity.did.clone())
            .ok_or((StatusCode::NOT_FOUND, format!("no room `{room_id}`")))?
    };

    admission::issue_invitation(&demo, &room_did, &req.did)
        .await
        .map(Json)
        .map_err(|r| (r.status(), r.message))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinRequest {
    /// The visitor's own room `did:key`, minted in their browser.
    did: String,
    /// Their KeyPackage, base64url — the public half of an identity they keep privately.
    key_package: String,
    /// The invitation this room issued them.
    invitation: serde_json::Value,
}

/// Admit a member, over HTTP.
///
/// The same caveat as [`invite`]: `did` is a claim here, where over DIDComm it is proved by
/// the request's own `eddsa-jcs-2022` proof. The invitation check catches most of what that
/// would — an invitation names one subject and is not transferable — but "most of" is the
/// honest word, and the DIDComm carrier is the one with the property.
async fn join(
    State(demo): State<Rooms>,
    Path(room_id): Path<String>,
    Json(req): Json<JoinRequest>,
) -> Result<Json<admission::Admitted>, (StatusCode, String)> {
    let room_did = {
        let rooms = demo.rooms.lock().await;
        rooms
            .get(&room_id)
            .map(|r| r.identity.did.clone())
            .ok_or((StatusCode::NOT_FOUND, format!("no room `{room_id}`")))?
    };

    let request = admission::AdmissionRequest {
        room_did,
        member_did: req.did.clone(),
        // No transport identity on this carrier. Named as the member's own DID rather than
        // left empty so the field never reads as "some other party sent this".
        transport_did: req.did,
        key_package: Some(req.key_package),
        invitation: Some(req.invitation),
    };

    admission::admit(&demo, &request)
        .await
        .map(Json)
        .map_err(|r| (r.status(), r.message))
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

/// Commits a member has not applied yet.
///
/// `since` is the member's own epoch — what they are at, not what they want. Everything
/// after it is what they missed, which is a question only they can ask because only they
/// know where they are.
///
/// A member who never calls this stays readable at their own epoch and finds every newer
/// record refusing to open. That failure is silent and reads as corruption, which is why
/// the site catches up on open rather than waiting to be asked.
async fn commits(
    State(demo): State<Rooms>,
    Path(room_id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<CommitsQuery>,
) -> Result<Json<Vec<CommittedEpoch>>, (StatusCode, String)> {
    let rooms = demo.rooms.lock().await;
    let room = rooms
        .get(&room_id)
        .ok_or((StatusCode::NOT_FOUND, format!("no room `{room_id}`")))?;
    Ok(Json(
        room.commits
            .iter()
            .filter(|c| c.epoch > q.since)
            .cloned()
            .collect(),
    ))
}

#[derive(Deserialize)]
struct CommitsQuery {
    since: u32,
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
/// The rung travels with it. A host stores rungs it cannot read and serves them back to
/// members, which is what lets somebody who joined at epoch 5 read epoch 2 — they walk down
/// from the key they hold. Sending the epoch without the rung is what `FromJoin` looks
/// like, and it is what this demo did until the owner started driving a `SealedRoom`.
pub(crate) async fn mint_epoch(
    host_url: &str,
    owner: &RoomIdentity,
    room: &Room,
    epoch: u32,
    link: Option<&EpochLink>,
) -> Result<(), String> {
    let presentation = owner
        .present(&room.owner_authority, &room.owner_membership, "admin")
        .await?;
    let document = serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/rooms/epoch/mint/0.1",
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": {
            "roomId": room.identity.did,
            "epoch": epoch,
            "presentation": presentation,
            // The rung for this advance. Ciphertext to the host — the key that opens it is
            // the storage key of the epoch it names, which no host ever holds. What a host
            // learns from a rung is that an epoch happened, which it knew already.
            //
            // Absent for a room's first epoch, which has no predecessor to wrap.
            "link": link,
        },
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
    // What members are told. The host's DID when there is one — `room-host --mediator-did`
    // prints it at startup — and its URL otherwise.
    let member_host = std::env::var("ROOM_HOST_DID").unwrap_or_else(|_| host_url.clone());

    // A mediator to advertise, if there is one. Rooms become `did:peer:2` and carry a
    // `DIDCommMessaging` service naming it; without one they stay `did:key` and can only be
    // joined by somebody this site was already told about.
    //
    // Unset by default rather than pointed at something plausible: a room advertising
    // somewhere nobody listens fails at the join, while a room advertising nothing says so
    // before you try.
    let mediator_did = std::env::var("MEDIATOR_DID").ok();
    match &mediator_did {
        Some(m) => println!("rooms will advertise mediator {m}"),
        None => println!(
            "no MEDIATOR_DID — rooms will be did:key, so they advertise nowhere and can only \
             be joined through this sample's own catalogue"
        ),
    }

    // One owner for the whole sample. In a real deployment this is a person with a VTA;
    // the rooms' keys are held by them, which is exactly how `RoomKeySigner` works
    // server-side — a room signs, but its key lives in its owner's agent.
    // The owner is a party, not a room: nobody reaches it by resolving it here, so it needs
    // no service block.
    let owner = RoomIdentity::mint(None).expect("mint the owner's identity");
    println!("owner: {}", owner.did);

    let mut rooms = BTreeMap::new();
    for (id, label, member_actions) in [
        (
            "demo-library",
            "The Library — a shared reading room",
            &["read", "write"][..],
        ),
        (
            "demo-workshop",
            "The Workshop — notes an agent can recall",
            &["read", "write", "curate"][..],
        ),
    ] {
        // Identity first, then the group. A room is a DTG node before it is a set of keys,
        // and the order is forced: a host told about a room it named could never let it
        // leave.
        let identity =
            RoomIdentity::mint(mediator_did.as_deref()).expect("mint the room's identity");
        let group = RoomGroup::create(&identity.did).expect("create the demo room group");
        // Paired with the room's identifier here rather than earlier: a rung is bound to
        // its room in its associated data, and the group deliberately does not know which
        // room it is for — the same separation that put `room_id` on `SealedRoom` for
        // sealing records.
        let room = SealedRoom::new(identity.did.clone(), group);
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
                room,
                member_actions,
                owner_membership,
                owner_authority,
                spent_invitations: Vec::new(),
                commits: Vec::new(),
                records: BTreeMap::new(),
                next_version: 1,
            },
        );
    }
    match member_host.strip_prefix("did:") {
        Some(_) => println!("members will reach the host at {member_host}"),
        None => println!(
            "members will reach the host at {member_host} over HTTP — set ROOM_HOST_DID to \
             the DID `room-host --mediator-did` prints, and they reach it through the \
             mediator instead"
        ),
    }

    let rooms: Rooms = Arc::new(Demo {
        owner,
        host_url,
        member_host,
        rooms: Mutex::new(rooms),
    });

    // The owner listens as each room, so somebody who resolved the room's DID and read its
    // service block reaches the party that can admit them — knowing nothing else about this
    // sample, its catalogue, or its port. That is the half of "one site, any number of
    // rooms" HTTP could not carry.
    //
    // Not fatal if it fails. The demo is still worth running against its own catalogue, and
    // a process that refused to start because a remote mediator was down would be worse. But
    // it is said out loud, because a room advertising a mediator its owner never reached
    // looks joinable and is not.
    if let Some(mediator) = mediator_did.clone() {
        if let Err(e) = mediator::listen(rooms.clone(), mediator).await {
            eprintln!("warning: the owner is not listening on the mediator — {e}");
            eprintln!("         rooms still advertise it, so joining by DID will time out.");
        }
    }

    let web = std::env::var("DEMO_WEB_DIR").unwrap_or_else(|_| "../web".to_string());
    let app = Router::new()
        .route("/api/rooms", get(catalogue))
        .route("/api/rooms/{room_id}/invite", post(invite))
        .route("/api/rooms/{room_id}/join", post(join))
        .route("/api/rooms/{room_id}/next-version", get(next_version))
        .route("/api/rooms/{room_id}/commits", get(commits))
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
