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

/// One demo room: its group, and the ciphertext its members have stored.
struct Room {
    /// The room's identifier. A real room mints a `did:webvh` before it tells any host;
    /// this one is a fixed string, because a demo room that could not be linked to is a
    /// demo nobody can open twice.
    id: String,
    /// A human name for the catalogue.
    label: String,
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

type Rooms = Arc<Mutex<BTreeMap<String, Room>>>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CatalogueEntry {
    room_id: String,
    label: String,
    epoch: u32,
    members: usize,
}

async fn catalogue(State(rooms): State<Rooms>) -> Json<Vec<CatalogueEntry>> {
    let rooms = rooms.lock().await;
    Json(
        rooms
            .values()
            .map(|r| CatalogueEntry {
                room_id: r.id.clone(),
                label: r.label.clone(),
                epoch: (r.group.epoch() + 1) as u32,
                members: r.group.member_count(),
            })
            .collect(),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinRequest {
    /// The visitor's own `did:key`, minted in their browser.
    did: String,
    /// Their KeyPackage, base64url — the public half of an identity they keep privately.
    key_package: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinResponse {
    room_id: String,
    /// The Welcome, base64url. Sealed to the KeyPackage above and to nothing else.
    welcome: String,
    /// The room's epoch after the commit this admission produced.
    epoch: u32,
    /// Each step the owner took, so the site can show the ceremony rather than a spinner.
    steps: Vec<String>,
}

/// Admit anyone who asks — see the module docs on why that is stated rather than hidden.
async fn join(
    State(rooms): State<Rooms>,
    Path(room_id): Path<String>,
    Json(req): Json<JoinRequest>,
) -> Result<Json<JoinResponse>, (StatusCode, String)> {
    let mut rooms = rooms.lock().await;
    let room = rooms
        .get_mut(&room_id)
        .ok_or((StatusCode::NOT_FOUND, format!("no room `{room_id}`")))?;

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

    let epoch = (change.epoch + 1) as u32;
    Ok(Json(JoinResponse {
        room_id,
        welcome: B64.encode(welcome),
        epoch,
        steps: vec![
            format!("invitation issued to {}", req.did),
            "key package validated against the room's ciphersuite".into(),
            format!("member added — the group committed to epoch {epoch}"),
            "welcome sealed to that key package alone".into(),
        ],
    }))
}

async fn list_records(
    State(rooms): State<Rooms>,
    Path(room_id): Path<String>,
) -> Result<Json<Vec<Record>>, (StatusCode, String)> {
    let rooms = rooms.lock().await;
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
    let mut rooms = rooms.lock().await;
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
    let rooms = rooms.lock().await;
    let room = rooms
        .get(&room_id)
        .ok_or((StatusCode::NOT_FOUND, format!("no room `{room_id}`")))?;
    Ok(Json(serde_json::json!({ "nextVersion": room.next_version })))
}

#[tokio::main]
async fn main() {
    let mut rooms = BTreeMap::new();
    for (id, label) in [
        ("demo-library", "The Library — a shared reading room"),
        ("demo-workshop", "The Workshop — notes an agent can recall"),
    ] {
        let group = RoomGroup::create("did:key:zDemoOwner").expect("create the demo room group");
        rooms.insert(
            id.to_string(),
            Room {
                id: id.to_string(),
                label: label.to_string(),
                group,
                records: BTreeMap::new(),
                next_version: 1,
            },
        );
    }
    let rooms: Rooms = Arc::new(Mutex::new(rooms));

    let web = std::env::var("DEMO_WEB_DIR").unwrap_or_else(|_| "../web".to_string());
    let app = Router::new()
        .route("/api/rooms", get(catalogue))
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
