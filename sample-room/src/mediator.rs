//! The owner, listening on a mediator — so a room can be joined by somebody nobody told
//! this site about.
//!
//! # What this closes
//!
//! Working *in* a room was already carrier-free: a host needs nothing but the request, so
//! the site could always talk to a room it had never seen. **Admission could not.** It needs
//! the room's owner, and until this module the only way to reach the owner was the sample's
//! own HTTP catalogue — which means the site could only admit you to a room it was already
//! configured for. That is the opposite of "one site, any number of rooms".
//!
//! A `did:peer:2` room advertises a `DIDCommMessaging` service naming its mediator. This is
//! the other end of that advertisement: the owner connects to the same mediator as each
//! room, so a member who resolved the room's DID reaches the party that can admit them,
//! knowing nothing else.
//!
//! # One connection per room, and that is not an accident of the API
//!
//! A mediator addresses a DID, and the room *is* the DID a member resolved. So the owner
//! opens a profile per room rather than one for itself: a member writes to the room, and the
//! owner is the party that happens to answer for it. An owner listening under its own DID
//! would be reachable only by somebody who already knew the owner — which is the thing being
//! fixed.
//!
//! The ATM underneath is shared, so those profiles are sockets on one client rather than one
//! stack apiece.
//!
//! # Nothing here decides anything
//!
//! Every rule lives in [`crate::admission`], which the HTTP handlers call too. This module
//! unpacks, dispatches, and packs the reply. A check that existed only here would be a check
//! the other carrier does not have, and the two would drift the first time one was changed.

use std::sync::Arc;
use std::time::Duration;

use affinidi_secrets_resolver::SecretsResolver as _;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;

use crate::admission::{self, Refusal};
use crate::Demo;

/// How long to wait for the next inbound message before looping to check for shutdown.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Connect the owner to `mediator_did`, once per room it holds, and answer admission
/// requests until the process ends.
///
/// Failure to connect is reported and not fatal. A demo whose HTTP catalogue still works is
/// worth running; one that refuses to start because a remote mediator was unreachable is
/// not. What is *not* done is to carry on silently — a room advertising a mediator its owner
/// never reached is a room that looks joinable and is not.
pub async fn listen(demo: Arc<Demo>, mediator_did: String) -> Result<(), String> {
    let tdk = TDKSharedState::new(
        TDKConfig::builder()
            .build()
            .map_err(|e| format!("TDK config: {e}"))?,
    )
    .await
    .map_err(|e| format!("TDK init: {e}"))?;

    // Every room's keys, in one resolver. The signing key **and** the key-agreement key: a
    // party that can be written to over DIDComm has to decrypt as well as prove who it is,
    // and a resolver holding only the first authenticates messages it cannot open.
    {
        let rooms = demo.rooms.lock().await;
        for room in rooms.values() {
            for secret in room.identity.secrets() {
                tdk.secrets_resolver().insert(secret.clone()).await;
            }
        }
    }

    let atm = ATM::new(
        ATMConfig::builder()
            .build()
            .map_err(|e| format!("ATM config: {e}"))?,
        Arc::new(tdk),
    )
    .await
    .map_err(|e| format!("ATM init: {e}"))?;
    let atm = Arc::new(atm);

    let room_dids: Vec<String> = {
        let rooms = demo.rooms.lock().await;
        rooms.values().map(|r| r.identity.did.clone()).collect()
    };

    for room_did in room_dids {
        // A `did:key` room advertises no service block, so no member could have found this
        // address by resolving it. Listening under one would be listening at a number nobody
        // can look up.
        if !room_did.starts_with("did:peer:") {
            eprintln!(
                "warning: {room_did} is not a did:peer, so it advertises no mediator — not \
                 listening for it"
            );
            continue;
        }

        let profile = ATMProfile::new(&atm, None, room_did.clone(), Some(mediator_did.clone()))
            .await
            .map_err(|e| format!("profile for {room_did}: {e}"))?;
        // Registered with the ATM rather than held loose, so a shutdown can actually stop
        // this socket — the ATM stops websockets by walking its own profile map, and an
        // unregistered profile outlives every teardown and keeps reconnecting.
        let profile = atm
            .profile_add(&profile, false)
            .await
            .map_err(|e| format!("register {room_did}: {e}"))?;
        atm.profile_enable_websocket(&profile)
            .await
            .map_err(|e| format!("websocket for {room_did}: {e}"))?;

        println!("listening for {room_did} at {mediator_did}");

        let demo = demo.clone();
        let atm = atm.clone();
        let mediator_did = mediator_did.clone();
        tokio::spawn(async move {
            dispatch(demo, atm, profile, room_did, mediator_did).await;
        });
    }

    Ok(())
}

/// Receive → decide → reply, for one room, forever.
async fn dispatch(
    demo: Arc<Demo>,
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    room_did: String,
    mediator_did: String,
) {
    loop {
        let next = atm
            .message_pickup()
            .live_stream_next(&profile, Some(POLL_INTERVAL), true)
            .await;

        let Ok(Some((msg, _meta))) = next else {
            continue;
        };

        // Never answer a problem report. Replying to one feeds the mediator's own policy
        // back into the loop and spins.
        if msg.typ.contains("problem-report") || msg.typ.contains("report-problem") {
            continue;
        }
        // A forward envelope that arrived un-unwrapped is not an application message.
        if msg.typ == "https://didcomm.org/routing/2.0/forward" {
            continue;
        }

        // No sender, no reply — and no authenticated transport identity either, which is
        // half of what binds a request to its connection.
        let Some(sender) = msg.from.clone() else {
            continue;
        };

        let (reply_type, body) = match handle(&demo, &msg.typ, &msg.body, &sender).await {
            Ok(reply) => reply,
            Err(refusal) => (
                "https://didcomm.org/report-problem/2.0/problem-report".to_string(),
                serde_json::json!({ "code": refusal.code, "comment": refusal.message }),
            ),
        };

        let reply_id = uuid::Uuid::new_v4().to_string();
        let reply = Message::build(reply_id.clone(), reply_type, body)
            .from(room_did.clone())
            .to(sender.clone())
            .thid(msg.id.clone())
            .finalize();

        // Two hops, because the mediator refuses direct delivery of inner messages: authcrypt
        // the reply to the member, then wrap that in a `routing/2.0/forward` addressed to the
        // mediator, which unwraps it and queues the inner JWE for the member's pickup.
        let inner = match atm
            .pack_encrypted(&reply, &sender, Some(&room_did), Some(&room_did))
            .await
        {
            Ok((packed, _)) => packed,
            Err(e) => {
                eprintln!("could not pack a reply to {sender}: {e}");
                continue;
            }
        };

        if let Err(e) = atm
            .forward_and_send_message(
                &profile,
                false, // authcrypt the forward envelope
                &inner,
                Some(&reply_id),
                &mediator_did,
                &sender,
                None,
                None,
                false,
            )
            .await
        {
            eprintln!("could not send a reply to {sender}: {e}");
        }
    }
}

/// Dispatch one message to the admission logic.
///
/// `sender` is the authenticated transport DID — passed down rather than trusted from the
/// body, which is the entire reason the binding check can be made at all.
async fn handle(
    demo: &Demo,
    msg_type: &str,
    body: &serde_json::Value,
    sender: &str,
) -> Result<(String, serde_json::Value), Refusal> {
    match msg_type {
        admission::REQUEST_INVITATION => {
            let req = admission::verify_request(body, Some(sender)).await?;
            let invitation =
                admission::issue_invitation(demo, &req.room_did, &req.member_did).await?;
            Ok((admission::INVITATION.to_string(), invitation))
        }
        admission::REQUEST_ADMISSION => {
            let req = admission::verify_request(body, Some(sender)).await?;
            let admitted = admission::admit(demo, &req).await?;
            Ok((
                admission::ADMITTED.to_string(),
                serde_json::to_value(&admitted).map_err(|e| Refusal {
                    code: "e.p.msg.internal-error",
                    message: e.to_string(),
                })?,
            ))
        }
        other => Err(Refusal {
            code: "e.p.msg.not-found",
            message: format!(
                "`{other}` is not something a room's owner answers — this address speaks \
                 {}",
                admission::PROTOCOL
            ),
        }),
    }
}
