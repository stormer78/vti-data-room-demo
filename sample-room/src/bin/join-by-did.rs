//! Join a room knowing **nothing but its DID**.
//!
//! ```text
//! cargo run --bin join-by-did -- did:peer:2.Vz6Mk…          # over DIDComm
//! cargo run --bin join-by-did -- --tsp did:peer:2.Vz6Mk…    # over TSP
//! ```
//!
//! Both carriers reach the same owner on the same socket — a mediator permits one websocket
//! per DID and multiplexes the two onto it. `--tsp` exists so the owner's TSP arm can be
//! exercised without a browser, and so the two can be compared: the ceremony below does not
//! change, only the packing.
//!
//! No host URL, no catalogue, no configuration. Everything else is derived:
//!
//! 1. Resolve the room's `did:peer` — pure computation, no network — and read the mediator
//!    out of its `DIDCommMessaging` service block.
//! 2. Mint the two identities a member holds: a **transport** `did:peer:2` for the mediator,
//!    and a **room** `did:key` for what the credentials will name.
//! 3. Ask to join, over DIDComm, and get a VIC back.
//! 4. Verify that VIC before minting anything — the same six clauses the browser's gate runs.
//! 5. Present it with a KeyPackage, and get a Welcome.
//! 6. Join the group, and print the epoch we landed at.
//!
//! # What this is for
//!
//! It is the member half of the protocol in [`dataroom_sample_room`], and it exists so the
//! owner's half can be proved against something before a browser is written against it. It
//! is also the reference: the JavaScript member does exactly these steps, and where the two
//! disagree this one is the one that has been run.
//!
//! It is deliberately *not* the demo. A real member is a browser; this is a person with a
//! terminal, which is a party the demo does not otherwise have.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_core::{MessageTransport, Protocol};
use affinidi_messaging_sdk::DidCommTransport;
use affinidi_secrets_resolver::SecretsResolver as _;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use dataroom_sample_room as wire;
use futures_lite::StreamExt as _;

/// How long to wait for the owner to answer before giving up.
///
/// Generous, and one number for both round trips: the second involves an MLS commit and a
/// call to the host, so a timeout tuned to the first would report the owner as absent while
/// it was working.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let over_tsp = args.iter().any(|a| a == "--tsp");
    let room_did = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .ok_or("usage: join-by-did [--tsp] <room did:peer>")?;

    // 1. Where is this room's owner, and over what? The room's own identifier says both.
    let advertised = wire::advertised_mediator(&room_did)?.ok_or_else(|| {
        format!(
            "`{room_did}` advertises no service, so there is nowhere to ask to join. A \
             `did:key` room can be verified but not reached."
        )
    })?;
    let mediator = advertised.mediator.clone();
    // `--tsp` forces the carrier; without it, take the best one the room says it serves.
    // Asking for a carrier a room does not advertise is allowed and is said out loud — it is
    // how you find out whether an owner serves more than it admits to.
    let carrier = if over_tsp {
        if !advertised.tsp {
            eprintln!("note: this room does not advertise TSP — asking over it anyway");
        }
        "tsp"
    } else {
        advertised.preferred().ok_or_else(|| {
            format!("`{room_did}` advertises a mediator but no carrier this build speaks")
        })?
    };
    println!("room      {room_did}");
    println!("mediator  {mediator}");

    // 2. Two identities, and they do different jobs — see the library docs.
    let member = MemberKey::mint()?;
    let (transport_did, transport_secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::Ed25519),
            (PeerKeyRole::Encryption, KeyType::X25519),
        ],
        None,
    )
    .map_err(|e| format!("mint the transport identity: {e}"))?;
    println!("room key  {}", member.did);
    println!("transport {transport_did}");

    println!(
        "carrier   {}  (room advertises{}{})",
        carrier,
        if advertised.tsp { " TSP" } else { "" },
        if advertised.didcomm { " DIDComm" } else { "" },
    );
    let client =
        Client::connect(&mediator, &transport_did, transport_secrets, carrier == "tsp").await?;

    // 3. Ask.
    let request = member
        .sign(&wire::AdmissionRequest {
            room_did: room_did.clone(),
            member_did: member.did.clone(),
            transport_did: transport_did.clone(),
            key_package: None,
            invitation: None,
        })
        .await?;
    let reply = client
        .ask(&room_did, wire::REQUEST_INVITATION, request)
        .await?;
    let (typ, body) = expect(reply, wire::INVITATION)?;
    println!("\n{typ}");
    let invitation = body
        .get("invitation")
        .cloned()
        .ok_or("the owner's reply carried no invitation")?;

    // 4. Check it before minting anything. **This gate defends this key holder**, not the
    //    room: minting a KeyPackage retains a private key against a Welcome that may never
    //    come, and accepting an uninvited Welcome would hold keys for a room nobody agreed
    //    to join. The room's own protection is separate and lives at the owner.
    check_invitation(&invitation, &room_did, &member.did)?;
    println!("invitation verified — issued by this room, to this key, in window, signed by the room");

    // 5. Present it, with a key package minted for this member's room DID.
    let (identity, key_package) = vti_rooms::mls::IdentitySnapshot::mint(&member.did)
        .map_err(|e| format!("mint an MLS identity: {e}"))?;
    let request = member
        .sign(&wire::AdmissionRequest {
            room_did: room_did.clone(),
            member_did: member.did.clone(),
            transport_did,
            key_package: Some(B64.encode(&key_package)),
            invitation: Some(invitation),
        })
        .await?;
    let reply = client
        .ask(&room_did, wire::REQUEST_ADMISSION, request)
        .await?;
    let (typ, body) = expect(reply, wire::ADMITTED)?;
    println!("\n{typ}");
    let admitted: wire::Admitted =
        serde_json::from_value(body).map_err(|e| format!("the owner's reply: {e}"))?;
    for step in &admitted.steps {
        println!("  · {step}");
    }

    // 6. Join, with the identity whose key package the owner used. `RoomGroup::join` would
    //    mint a fresh one, which the Welcome is not sealed to.
    let welcome = B64
        .decode(admitted.welcome.as_bytes())
        .map_err(|e| format!("welcome: {e}"))?;
    let group = vti_rooms::mls::RoomGroup::join_from_identity(&identity, &welcome)
        .map_err(|e| format!("join the group: {e}"))?;
    // What a member actually holds: the group **and** its epoch key chain. A bare
    // `RoomGroup` mints no rungs, so a member who kept one could read only from where they
    // joined — and it counts in MLS epochs, which start at 0 where a room's start at 1.
    // Reading `room_epoch()` is what makes this number comparable to the owner's.
    let room = vti_rooms::sealed::SealedRoom::new(room_did.clone(), group);

    println!("\njoined `{}` at epoch {}", admitted.room_id, admitted.epoch);
    println!("this member is at room epoch {}", room.room_epoch());
    println!(
        "granted     {}",
        admitted
            .authority
            .pointer("/credentialSubject/authority/actions")
            .and_then(|a| a.as_array())
            .map(|a| a
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", "))
            .unwrap_or_else(|| "—".into())
    );
    Ok(())
}

/// The member's **room identity**: an Ed25519 key and the `did:key` it names.
///
/// Self-certifying, so the owner verifies what it signs by arithmetic on the identifier — no
/// resolution, and nothing for an owner to fetch on an unauthenticated request.
struct MemberKey {
    did: String,
    secret: affinidi_secrets_resolver::secrets::Secret,
}

impl MemberKey {
    fn mint() -> Result<Self, String> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| format!("no randomness: {e}"))?;
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();

        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(&public);
        let did = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &multicodec)
        );

        // The `did:key` convention: the multibase tag IS the verification-method fragment.
        let secret = affinidi_secrets_resolver::secrets::Secret::from_str(
            &format!("{did}#{}", &did["did:key:".len()..]),
            &serde_json::json!({
                "crv": "Ed25519",
                "d": B64.encode(signing.to_bytes()),
                "kty": "OKP",
                "x": B64.encode(public),
            }),
        )
        .map_err(|e| format!("build the member's signing secret: {e}"))?;

        Ok(Self { did, secret })
    }

    /// Attach this key's `eddsa-jcs-2022` proof to a request.
    ///
    /// What proves the *room* identity authored it, as distinct from what DIDComm proves
    /// about the transport identity that carried it.
    async fn sign(&self, request: &wire::AdmissionRequest) -> Result<serde_json::Value, String> {
        let mut doc =
            serde_json::to_value(request).map_err(|e| format!("serialise the request: {e}"))?;
        let proof = affinidi_data_integrity::DataIntegrityProof::sign(
            &doc,
            &self.secret,
            affinidi_data_integrity::SignOptions::new(),
        )
        .await
        .map_err(|e| format!("sign the request: {e}"))?;
        doc.as_object_mut()
            .ok_or("a request must be a JSON object")?
            .insert(
                "proof".into(),
                serde_json::to_value(&proof).map_err(|e| e.to_string())?,
            );
        Ok(doc)
    }
}

/// The member's MLS identity, kept across both round trips.
///
/// One `IdentitySnapshot` throughout, deliberately: the owner adds the key package minted
/// with it, and a Welcome is sealed to *that* key package. Joining with a second identity
/// produces a group whose leaf nobody added, which fails at the first read looking like a
/// bad Welcome rather than a wrong identity.
///
/// One per room, too. A KeyPackage is a stable public identifier, so the same one offered to
/// two rooms tells anyone who sees both that one party is in both.
/// The six clauses, in the order the browser's gate runs them: the cheap structural checks
/// first, then the signature, so a credential that was never about us costs nothing.
///
/// The spent-set is the browser's seventh and there is nothing to keep it in here — a
/// process that exits cannot replay itself.
fn check_invitation(
    invitation: &serde_json::Value,
    room_did: &str,
    member_did: &str,
) -> Result<(), String> {
    use dtg_credentials::{DTGCredential, DTGCredentialType};

    let credential: DTGCredential = serde_json::from_value(invitation.clone())
        .map_err(|e| format!("the invitation is not a credential: {e}"))?;

    if !matches!(credential.type_(), DTGCredentialType::Invitation) {
        return Err(format!(
            "the owner sent a {}, not an invitation",
            credential.type_()
        ));
    }
    if credential.issuer() != room_did {
        return Err(format!(
            "the invitation was issued by `{}`, not by room `{room_did}`",
            credential.issuer()
        ));
    }
    if credential.subject() != member_did {
        return Err(format!(
            "the invitation names `{}`, not this key — an invitation is not transferable",
            credential.subject()
        ));
    }

    let now = chrono::Utc::now();
    let common = credential.credential();
    if common.valid_from > now {
        return Err("the invitation is not valid yet".into());
    }
    if let Some(until) = common.valid_until
        && until < now
    {
        return Err("the invitation has expired".into());
    }

    let proof = common
        .proof
        .as_ref()
        .ok_or("the invitation carries no proof")?;
    // The proof's key must belong to the **issuer**, and nothing above implies it. Without
    // this an attacker mints an invitation naming the room, signs it with their own key,
    // points the proof at their own method, and every other clause passes.
    let vm_controller = proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or(&proof.verification_method);
    if vm_controller != credential.issuer() {
        return Err(format!(
            "the invitation says room `{}` issued it but is signed by `{vm_controller}` — a \
             proof that verifies only means somebody signed it, not that the issuer did",
            credential.issuer()
        ));
    }

    let key = room_verification_key(&proof.verification_method)?;
    credential
        .verify_proof_with_public_key(&key)
        .map_err(|e| format!("the invitation's proof did not verify: {e}"))?;
    Ok(())
}

/// The Ed25519 key a room's verification method names, with **no network** — the room
/// carries it in its own identifier, whichever of the two methods it is.
fn room_verification_key(verification_method: &str) -> Result<Vec<u8>, String> {
    let did = verification_method
        .split('#')
        .next()
        .unwrap_or(verification_method);

    if let Some(multibase) = did.strip_prefix("did:key:") {
        let (_base, bytes) =
            multibase::decode(multibase).map_err(|e| format!("decode `{did}`: {e}"))?;
        return match bytes.split_at_checked(2) {
            Some(([0xed, 0x01], key)) if key.len() == 32 => Ok(key.to_vec()),
            _ => Err(format!("`{did}` does not name an Ed25519 key")),
        };
    }

    use affinidi_did_common::DID;
    use affinidi_did_resolver_traits::{PeerResolver, Resolver};
    let parsed =
        DID::try_from(did).map_err(|e| format!("`{did}` is not a well-formed DID: {e}"))?;
    let doc = PeerResolver
        .resolve(&parsed)
        .ok_or_else(|| format!("`{did}` is not a did:peer this build resolves"))?
        .map_err(|e| format!("`{did}` did not resolve: {e}"))?;

    // A proof names a method absolutely; a document may name it relatively. Accept both
    // spellings rather than requiring the document to have chosen ours.
    let relative = verification_method
        .split_once('#')
        .map(|(_, fragment)| format!("#{fragment}"))
        .unwrap_or_default();
    doc.verification_method
        .iter()
        .find(|m| m.id.as_str() == verification_method || m.id.as_str() == relative)
        .ok_or_else(|| format!("`{verification_method}` is not in the document for `{did}`"))?
        .get_public_key_bytes()
        .map_err(|e| format!("`{verification_method}` public key: {e}"))
}

/// One connection to a mediator, under the transport identity, carrying either protocol.
///
/// One socket for both, because that is all a mediator gives: it permits one websocket per
/// DID and sniffs the TSP magic byte to route what arrives. The inbound side goes through
/// the delivery layer's `DidCommTransport`, whose stream surfaces both tagged by protocol —
/// the ATM's own pickup surfaces DIDComm only, and a client using it would wait forever for
/// a TSP reply that had already arrived.
struct Client {
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    transport: DidCommTransport,
    transport_did: String,
    mediator_did: String,
    over_tsp: bool,
}

impl Client {
    async fn connect(
        mediator_did: &str,
        transport_did: &str,
        secrets: Vec<affinidi_secrets_resolver::secrets::Secret>,
        over_tsp: bool,
    ) -> Result<Self, String> {
        let tdk = TDKSharedState::new(
            TDKConfig::builder()
                .build()
                .map_err(|e| format!("TDK config: {e}"))?,
        )
        .await
        .map_err(|e| format!("TDK init: {e}"))?;
        for secret in &secrets {
            tdk.secrets_resolver().insert(secret.clone()).await;
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

        let profile = ATMProfile::new(
            &atm,
            None,
            transport_did.to_string(),
            Some(mediator_did.to_string()),
        )
        .await
        .map_err(|e| format!("profile: {e}"))?;
        let profile = atm
            .profile_add(&profile, false)
            .await
            .map_err(|e| format!("register the profile: {e}"))?;
        atm.profile_enable_websocket(&profile)
            .await
            .map_err(|e| format!("websocket: {e}"))?;

        let transport = DidCommTransport::new((*atm).clone(), profile.clone())
            .await
            .map_err(|e| format!("bind the transport: {e}"))?;

        Ok(Self {
            atm,
            profile,
            transport,
            transport_did: transport_did.to_string(),
            mediator_did: mediator_did.to_string(),
            over_tsp,
        })
    }

    /// Send one message to the room and wait for the reply threaded to it.
    ///
    /// Threaded rather than "the next message that arrives": a mediator delivers status
    /// messages and pings of its own, and a client that took the first thing off the socket
    /// would read one of those as the owner's answer.
    async fn ask(
        &self,
        room_did: &str,
        msg_type: &str,
        body: serde_json::Value,
    ) -> Result<(String, serde_json::Value), String> {
        let id = uuid::Uuid::new_v4().to_string();
        if self.over_tsp {
            self.send_tsp(room_did, &id, msg_type, body).await?;
        } else {
            self.send_didcomm(room_did, &id, msg_type, body).await?;
        }
        self.await_reply(room_did, &id).await
    }

    /// DIDComm: authcrypt to the room, then wrap in a `routing/2.0/forward` addressed to the
    /// mediator, which unwraps it and queues the inner envelope for the room's pickup. Two
    /// hops, because a mediator refuses direct delivery of inner messages.
    async fn send_didcomm(
        &self,
        room_did: &str,
        id: &str,
        msg_type: &str,
        body: serde_json::Value,
    ) -> Result<(), String> {
        let msg = Message::build(id.to_string(), msg_type.to_string(), body)
            .from(self.transport_did.clone())
            .to(room_did.to_string())
            .finalize();

        let (inner, _) = self
            .atm
            .pack_encrypted(
                &msg,
                room_did,
                Some(&self.transport_did),
                Some(&self.transport_did),
            )
            .await
            .map_err(|e| format!("pack the request: {e}"))?;

        self.atm
            .forward_and_send_message(
                &self.profile,
                false,
                &inner,
                Some(id),
                &self.mediator_did,
                room_did,
                None,
                None,
                false,
            )
            .await
            .map(|_| ())
            .map_err(|e| format!("send the request: {e}"))
    }

    /// TSP: sealed end-to-end to the room and routed through the mediator, which carries it
    /// without being able to read it.
    ///
    /// The envelope is `{ id, type, body }` in the payload, because TSP has no headers —
    /// DIDComm supplies `type` and `thid` around the message, and over TSP the message has
    /// to carry them itself. Same three fields either way, which is what lets the owner
    /// hand both to one decision.
    async fn send_tsp(
        &self,
        room_did: &str,
        id: &str,
        msg_type: &str,
        body: serde_json::Value,
    ) -> Result<(), String> {
        let envelope = serde_json::json!({ "id": id, "type": msg_type, "body": body });
        let bytes = serde_json::to_vec(&envelope).map_err(|e| e.to_string())?;
        self.atm
            .tsp()
            .send_routed(
                &self.profile,
                &[self.mediator_did.clone(), room_did.to_string()],
                &bytes,
            )
            .await
            .map_err(|e| format!("send the TSP request: {e}"))
    }

    /// Wait for the reply threaded to `id`, on whichever protocol it comes back on.
    async fn await_reply(
        &self,
        room_did: &str,
        id: &str,
    ) -> Result<(String, serde_json::Value), String> {
        let mut inbound = self.transport.inbound();
        let deadline = tokio::time::Instant::now() + REPLY_TIMEOUT;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "the owner of `{room_did}` did not answer within {}s — the room advertises \
                     this mediator, but nothing is listening there for it",
                    REPLY_TIMEOUT.as_secs()
                ));
            }

            let Ok(Some(frame)) = tokio::time::timeout(remaining, inbound.next()).await else {
                continue;
            };
            let _ = self.transport.ack(frame.ack.clone()).await;

            let Ok(envelope) =
                serde_json::from_slice::<serde_json::Value>(&frame.message.payload)
            else {
                continue;
            };

            // DIDComm threads in the envelope's own `thid`; TSP has no header to thread it,
            // so the reply carries one. Accept either, and never "the next frame" — the
            // mediator's own status messages arrive on this socket too.
            let threaded = frame
                .thread_id
                .clone()
                .or_else(|| {
                    envelope
                        .get("thid")
                        .and_then(|t| t.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_default();
            if threaded != id {
                continue;
            }

            let typ = envelope
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or_default()
                .to_string();
            let body = envelope
                .get("body")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            if typ.contains("problem-report") {
                let code = body.get("code").and_then(|c| c.as_str()).unwrap_or("(no code)");
                let comment = body
                    .get("comment")
                    .and_then(|c| c.as_str())
                    .unwrap_or("(no comment)");
                return Err(format!("the owner refused [{code}]: {comment}"));
            }

            // Said out loud, because a reply arriving on the other protocol from the one the
            // request went out on is exactly the kind of thing worth noticing rather than
            // silently accepting.
            if matches!(frame.message.protocol, Protocol::TSP) != self.over_tsp {
                eprintln!("note: the reply came back on the other protocol");
            }
            return Ok((typ, body));
        }
    }
}

/// A reply of the type this step asked for, or a message saying which it got instead.
fn expect(
    reply: (String, serde_json::Value),
    expected: &str,
) -> Result<(String, serde_json::Value), String> {
    let (typ, body) = reply;
    if typ != expected {
        return Err(format!("expected `{expected}`, got `{typ}`"));
    }
    Ok((typ, body))
}
