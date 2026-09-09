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
//! # Two protocols, one socket
//!
//! A mediator permits **one websocket per DID**, and multiplexes TSP and DIDComm onto it —
//! it sniffs the TSP magic byte and routes accordingly. So this listens through the delivery
//! layer's `DidCommTransport`, whose `inbound()` surfaces both, tagged by [`Protocol`],
//! rather than through the ATM's DIDComm-only pickup. Opening a second socket for TSP is
//! not an alternative: the mediator evicts one of them as a duplicate channel and the owner
//! flaps.
//!
//! TSP is the higher-preference transport of the two, and a member reaching a room this way
//! gets a stronger guarantee for free: the sender VID is proven by the TSP unpack itself,
//! where DIDComm's authcrypt proves it at the envelope. The admission logic does not care —
//! it is handed a proven sender either way, which is the whole reason the two carriers can
//! share one implementation.
//!
//! # Nothing here decides anything
//!
//! Every rule lives in [`crate::admission`], which the HTTP handlers call too. This module
//! unpacks, dispatches, and packs the reply. A check that existed only here would be a check
//! the other carrier does not have, and the two would drift the first time one was changed.

use std::sync::Arc;

use affinidi_messaging_core::{Inbound, MessageTransport, Protocol};
use affinidi_messaging_sdk::DidCommTransport;
use affinidi_secrets_resolver::SecretsResolver as _;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use futures_lite::StreamExt as _;

use crate::admission::{self, Refusal};
use crate::Demo;

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

        // The delivery layer over that one socket. Both protocols arrive through it.
        let transport = DidCommTransport::new((*atm).clone(), profile.clone())
            .await
            .map_err(|e| format!("bind the transport for {room_did}: {e}"))?;

        println!("listening for {room_did} at {mediator_did} (DIDComm + TSP)");

        let demo = demo.clone();
        let atm = atm.clone();
        let mediator_did = mediator_did.clone();
        tokio::spawn(async move {
            dispatch(demo, atm, profile, transport, room_did, mediator_did).await;
        });
    }

    Ok(())
}

/// Receive → decide → reply, for one room, forever, over whichever protocol it arrived on.
///
/// One loop for both carriers, because the mediator gives one socket and the delivery layer
/// tags each frame with the protocol it came in on. What differs is only the packing: the
/// decision is the same call, and the sender is proven either way.
async fn dispatch(
    demo: Arc<Demo>,
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    transport: DidCommTransport,
    room_did: String,
    mediator_did: String,
) {
    let mut inbound = transport.inbound();

    while let Some(frame) = inbound.next().await {
        // The delivery layer only surfaces a sender it has authenticated — DIDComm's
        // authcrypt, or TSP's own unpack. An unauthenticated frame has nobody to answer and
        // nothing to bind a request to, which is half of what makes admission safe.
        let Some(sender) = frame.message.sender.clone() else {
            continue;
        };
        if !frame.message.verified {
            continue;
        }

        match frame.message.protocol {
            Protocol::TSP => {
                answer_tsp(&demo, &atm, &profile, &mediator_did, &sender, &frame).await;
            }
            _ => {
                answer_didcomm(&demo, &atm, &profile, &room_did, &mediator_did, &sender, &frame)
                    .await;
            }
        }

        // Acked after the reply is sent, not before: the ack is what makes the mediator
        // delete its copy, so acking first would lose a request whose answer never left.
        let _ = transport.ack(frame.ack.clone()).await;
    }
}

/// The DIDComm arm: unpack the plaintext, decide, and send the reply back through the
/// mediator.
async fn answer_didcomm(
    demo: &Demo,
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    room_did: &str,
    mediator_did: &str,
    sender: &str,
    frame: &Inbound,
) {
    let Ok(msg) = serde_json::from_slice::<serde_json::Value>(&frame.message.payload) else {
        return;
    };
    let msg_type = msg.get("type").and_then(|t| t.as_str()).unwrap_or_default();

    // Never answer a problem report — replying to one feeds the mediator's own policy back
    // into the loop and spins. A forward envelope that arrived un-unwrapped is not an
    // application message either.
    if msg_type.contains("problem-report")
        || msg_type.contains("report-problem")
        || msg_type == "https://didcomm.org/routing/2.0/forward"
    {
        return;
    }
    let body = msg.get("body").cloned().unwrap_or(serde_json::Value::Null);
    let thid = msg
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or_default()
        .to_string();

    let (reply_type, reply_body) = match handle(demo, msg_type, &body, sender).await {
        Ok(reply) => reply,
        Err(refusal) => problem_report(&refusal),
    };

    let reply_id = uuid::Uuid::new_v4().to_string();
    let reply = Message::build(reply_id.clone(), reply_type, reply_body)
        .from(room_did.to_string())
        .to(sender.to_string())
        .thid(thid)
        .finalize();

    // Two hops, because the mediator refuses direct delivery of inner messages: authcrypt
    // the reply to the member, then wrap that in a `routing/2.0/forward` addressed to the
    // mediator, which unwraps it and queues the inner envelope for the member's pickup.
    let inner = match atm
        .pack_encrypted(&reply, sender, Some(room_did), Some(room_did))
        .await
    {
        Ok((packed, _)) => packed,
        Err(e) => {
            eprintln!("could not pack a reply to {sender}: {e}");
            return;
        }
    };

    if let Err(e) = atm
        .forward_and_send_message(
            profile,
            false, // authcrypt the forward envelope
            &inner,
            Some(&reply_id),
            mediator_did,
            sender,
            None,
            None,
            false,
        )
        .await
    {
        eprintln!("could not send a reply to {sender}: {e}");
    }
}

/// The TSP arm: the payload *is* the envelope, and the reply is sealed straight back.
///
/// # Why the envelope is spelled out here
///
/// TSP carries an opaque payload and no headers — no `type`, no `thid`. DIDComm supplies
/// both, so over that carrier the protocol needs no framing of its own. Over TSP something
/// has to say which message this is, so the payload is `{ id, type, body }` — the same three
/// fields, in the message itself rather than around it.
///
/// That is not a second protocol. `handle` takes the same type string and the same body
/// whichever arm called it, which is the property worth keeping: a rule that held on one
/// carrier and not the other would be a hole with a transport for a key.
async fn answer_tsp(
    demo: &Demo,
    atm: &Arc<ATM>,
    profile: &Arc<ATMProfile>,
    mediator_did: &str,
    sender: &str,
    frame: &Inbound,
) {
    let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(&frame.message.payload) else {
        return;
    };
    let msg_type = envelope
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or_default();
    let body = envelope
        .get("body")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let thid = envelope
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or_default()
        .to_string();

    let (reply_type, reply_body) = match handle(demo, msg_type, &body, sender).await {
        Ok(reply) => reply,
        Err(refusal) => problem_report(&refusal),
    };

    let reply = serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "type": reply_type,
        // Threaded to the request, because TSP has no header to thread it for us and a
        // member with two asks outstanding cannot otherwise tell the answers apart.
        "thid": thid,
        "body": reply_body,
    });
    let Ok(bytes) = serde_json::to_vec(&reply) else {
        return;
    };

    // Sealed end-to-end to the member and routed through the mediator, which carries it
    // without being able to read it.
    if let Err(e) = atm
        .tsp()
        .send_routed(
            profile,
            &[mediator_did.to_string(), sender.to_string()],
            &bytes,
        )
        .await
    {
        eprintln!("could not send a TSP reply to {sender}: {e}");
    }
}

/// A refusal, in the shape both carriers report one.
fn problem_report(refusal: &Refusal) -> (String, serde_json::Value) {
    (
        "https://didcomm.org/report-problem/2.0/problem-report".to_string(),
        serde_json::json!({ "code": refusal.code, "comment": refusal.message }),
    )
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
