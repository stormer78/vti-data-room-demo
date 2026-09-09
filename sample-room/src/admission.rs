//! Admission — being let into a room, and the two acts it takes.
//!
//! Asking to join and being admitted are the same two steps whichever way they arrive, so
//! they live here once and the carriers call them. `main.rs` exposes them over HTTP for the
//! sample's own catalogue; `mediator.rs` exposes them over DIDComm for anybody who has
//! nothing but the room's DID. **Neither carrier holds a rule the other does not** — that
//! is the whole reason this module exists rather than a second copy of `join` living in the
//! listener.
//!
//! # The decisions, not the wire
//!
//! The message types and their bodies live in the crate library, because two different
//! parties speak them — see [`dataroom_sample_room`], which also explains why they are a
//! plain DIDComm protocol rather than Trust Tasks, and what binds a member's two identities
//! together. This module is what an owner *decides* when one arrives.
//!
//! Over HTTP there is no authenticated transport identity to check that binding against, and
//! this module says so rather than pretending: the sample's own catalogue is a local
//! convenience, and the DIDComm path is the one with the property.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
pub use dataroom_sample_room::{
    ADMITTED, AdmissionRequest, Admitted, COMMITS, INVITATION, PROTOCOL, REQUEST_ADMISSION,
    REQUEST_COMMITS, REQUEST_INVITATION,
};

use crate::{CommittedEpoch, Demo};

/// A refusal, and the code it travels as.
///
/// `e.p.msg.*`, the DIDComm problem-report vocabulary. It used to carry a `status()` mapping
/// to HTTP as well, for the second admission path this site had; that path is gone and so is
/// the mapping. One admission implementation means one vocabulary for saying no.
#[derive(Debug)]
pub struct Refusal {
    pub code: &'static str,
    pub message: String,
}

impl Refusal {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Something is wrong with what was sent.
    fn bad_request(message: impl Into<String>) -> Self {
        Self::new("e.p.msg.bad-request", message)
    }

    /// The request is well-formed and the answer is no.
    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new("e.p.msg.unauthorized", message)
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new("e.p.msg.not-found", message)
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self::new("e.p.msg.conflict", message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new("e.p.msg.internal-error", message)
    }
}

/// Check a request's own proof, and bind it to the connection it arrived on.
///
/// `sender` is the DIDComm `from` — `None` over HTTP, where there is no such thing and the
/// binding therefore cannot be checked. That is stated as a parameter rather than hidden
/// behind a default so a carrier cannot forget to pass it and quietly get the weaker check.
pub async fn verify_request(
    body: &serde_json::Value,
    sender: Option<&str>,
) -> Result<AdmissionRequest, Refusal> {
    let req: AdmissionRequest = serde_json::from_value(body.clone())
        .map_err(|e| Refusal::bad_request(format!("admission request: {e}")))?;

    // The room identity signs; the proof is over the body without itself.
    let proof = body
        .get("proof")
        .ok_or_else(|| Refusal::bad_request("the request carries no proof of your room key"))?;
    let proof: affinidi_data_integrity::DataIntegrityProof = serde_json::from_value(proof.clone())
        .map_err(|e| Refusal::bad_request(format!("the request's proof: {e}")))?;

    // The proof must name the member's own key — not merely *a* key that verifies. A proof
    // pointing anywhere else means somebody signed this, which is true of every forgery.
    let vm_controller = proof
        .verification_method
        .split('#')
        .next()
        .unwrap_or(&proof.verification_method);
    if vm_controller != req.member_did {
        return Err(Refusal::unauthorized(format!(
            "the request says `{}` is asking but is signed by `{vm_controller}`",
            req.member_did
        )));
    }

    let mut unsigned = body.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| Refusal::bad_request("an admission request must be a JSON object"))?
        .remove("proof");

    // `did:key` only, and resolved by arithmetic — a member is a stranger with a link, and
    // an owner that resolved whatever DID a stranger named would fetch on an unauthenticated
    // request. The same posture `room-host` takes on the other side.
    proof
        .verify(
            &unsigned,
            &affinidi_data_integrity::did_vm::DidKeyResolver,
            affinidi_data_integrity::VerifyOptions::default(),
        )
        .await
        .map_err(|e| Refusal::unauthorized(format!("the request's proof did not verify: {e}")))?;

    // The binding. Without it a signed request is a bearer artefact: anybody who saw one
    // could send it from their own transport identity and be handed the reply.
    if let Some(sender) = sender
        && sender != req.transport_did
    {
        return Err(Refusal::unauthorized(format!(
            "this request was signed for a connection from `{}` but arrived from `{sender}` \
             — a signed request is not a bearer token",
            req.transport_did
        )));
    }

    Ok(req)
}

/// Find a room by its DID, which is how anybody who is not this sample refers to it.
///
/// The catalogue's slugs are a local convenience; a member who was handed a link holds the
/// DID and nothing else. Looking up by DID here is what makes the two carriers agree about
/// what a room is.
async fn room_id_for_did(demo: &Demo, room_did: &str) -> Result<String, Refusal> {
    let rooms = demo.rooms.lock().await;
    rooms
        .values()
        .find(|r| r.identity.did == room_did)
        .map(|r| r.id.clone())
        .ok_or_else(|| Refusal::not_found(format!("this owner holds no room `{room_did}`")))
}

/// Issue an invitation to the DID that asked for one.
///
/// A demo room admits anyone who asks and says so on screen. What is not faked is the
/// artefact: a real DTG credential, signed by the room, naming one subject, valid for an
/// hour, single-use. A real owner decides whether to call this; every step either side is
/// identical.
///
/// The subject is the **room** identity, never the transport one. The VIC is later presented
/// alongside documents signed by the room key, and a credential naming the wrong one of a
/// member's two keys is a credential they can never use.
pub async fn issue_invitation(
    demo: &Demo,
    room_did: &str,
    member_did: &str,
) -> Result<serde_json::Value, Refusal> {
    let rooms = demo.rooms.lock().await;
    let room = rooms
        .values()
        .find(|r| r.identity.did == room_did)
        .ok_or_else(|| Refusal::not_found(format!("this owner holds no room `{room_did}`")))?;

    let invitation = room
        .identity
        .invite(member_did)
        .await
        .map_err(Refusal::internal)?;

    Ok(serde_json::json!({
        "roomDid": room.identity.did,
        "roomId": room.id,
        "label": room.label,
        "grants": room.member_actions,
        "invitation": serde_json::from_str::<serde_json::Value>(&invitation)
            .map_err(|e| Refusal::internal(e.to_string()))?,
    }))
}

/// The commits a member has not applied yet.
///
/// `since` is the epoch they are **at**, not the one they want: everything after it is what
/// they missed, and that is a question only they can ask because only they know where they
/// are.
///
/// # Members only, and that is not paranoia about the bytes
///
/// A commit confers nothing on a non-member — it is handshake material that authenticates its
/// committer *inside* the group, and somebody outside cannot use one for anything. What it
/// does leak is that the room exists, how often its membership changes, and how long that
/// history is. That is the room's business, so the room decides who sees it, and the answer
/// is "people it admitted".
///
/// Checked against the room's own record of whom it issued membership to, rather than against
/// a presented credential: a member asking this has nothing to present that the owner did not
/// issue in the first place, so asking them for it would be asking them to hand back a fact
/// the owner already holds.
pub async fn commits_since(
    demo: &Demo,
    room_did: &str,
    member_did: &str,
    since: u32,
) -> Result<serde_json::Value, Refusal> {
    let rooms = demo.rooms.lock().await;
    let room = rooms
        .values()
        .find(|r| r.identity.did == room_did)
        .ok_or_else(|| Refusal::not_found(format!("this owner holds no room `{room_did}`")))?;

    if !room.members.iter().any(|m| m == member_did) {
        return Err(Refusal::unauthorized(
            "this room has not admitted you, so it has no history to give you",
        ));
    }

    Ok(serde_json::json!({
        "roomDid": room.identity.did,
        "commits": room
            .commits
            .iter()
            .filter(|c| c.epoch > since)
            .collect::<Vec<_>>(),
    }))
}

/// Admit a member: verify their invitation, add them to the group, and issue what governs
/// them.
///
/// The owner's half of the two-party invitation check. The member checked the same
/// invitation in their own browser and neither substitutes for the other: theirs stops their
/// key holder being filled with a room they never agreed to join, this one stops a replayed
/// or forged invitation adding a leaf.
pub async fn admit(demo: &Demo, req: &AdmissionRequest) -> Result<Admitted, Refusal> {
    let room_id = room_id_for_did(demo, &req.room_did).await?;
    let key_package = req
        .key_package
        .as_deref()
        .ok_or_else(|| Refusal::bad_request("an admission request must carry a key package"))?;
    let key_package = B64
        .decode(key_package.as_bytes())
        .map_err(|e| Refusal::bad_request(format!("key package: {e}")))?;
    let invitation = req
        .invitation
        .clone()
        .ok_or_else(|| Refusal::bad_request("an admission request must present an invitation"))?;

    let host_url = demo.host_url.clone();
    let mut rooms = demo.rooms.lock().await;
    let room = rooms
        .get_mut(&room_id)
        .ok_or_else(|| Refusal::not_found(format!("no room `{room_id}`")))?;

    let invitation: dtg_credentials::DTGCredential = serde_json::from_value(invitation)
        .map_err(|e| Refusal::bad_request(format!("invitation: {e}")))?;
    let credential_id = invitation
        .id()
        .ok_or_else(|| {
            Refusal::bad_request("the invitation carries no id, so single use cannot be enforced")
        })?
        .to_string();

    if invitation.issuer() != room.identity.did {
        return Err(Refusal::unauthorized(format!(
            "that invitation was issued by `{}`, not by this room",
            invitation.issuer()
        )));
    }
    if invitation.subject() != req.member_did {
        return Err(Refusal::unauthorized(format!(
            "that invitation names `{}`, not you — an invitation is not transferable",
            invitation.subject()
        )));
    }
    // Against the room's own key, which the owner holds. Not re-derived from the room's
    // identifier: that is a `did:key` or a `did:peer` depending on whether the room
    // advertises a mediator, and only a member — who has nothing but the identifier — has
    // to resolve it.
    invitation
        .verify_proof_with_public_key(room.identity.public_key())
        .map_err(|_| {
            Refusal::unauthorized("that invitation's proof does not verify against this room's key")
        })?;
    if room.spent_invitations.contains(&credential_id) {
        return Err(Refusal::conflict(format!(
            "invitation `{credential_id}` has already been used"
        )));
    }

    // Returns the rung alongside the commit, because the rung can only be minted in the one
    // moment any party holds both the outgoing epoch's key and the incoming one. Afterwards
    // it is unrecoverable — the outgoing key is gone.
    let (change, link) = room
        .room
        .add_member(&key_package)
        .map_err(|e| Refusal::bad_request(format!("add member: {e}")))?;

    // A removal produces no Welcome; an addition always does. If this is ever `None` the
    // member would join a group nobody added them to, which fails at the first read looking
    // like a bad Welcome rather than a wrong identity — so it is an error here instead.
    let welcome = change
        .welcome
        .ok_or_else(|| Refusal::internal("adding a member produced no Welcome"))?;

    let epoch = (change.epoch + 1) as u32;

    // Kept so members already in the room can catch up. A member added at epoch 3 needs
    // every commit from 4 onwards; one added at 5 needs none of them, because their Welcome
    // carried the group as it stood.
    room.commits.push(CommittedEpoch {
        epoch,
        commit: B64.encode(&change.commit),
    });

    // Consumed only now, after the join succeeded. Spending it earlier would burn an
    // invitation on a failed attempt and leave the member unable to retry.
    room.spent_invitations.push(credential_id);
    room.members.push(req.member_did.clone());

    // Membership and authority are separate acts because they are separate facts: being a
    // member is not being allowed to write. A demo visitor gets what the room grants and not
    // what it does not, so the room has a governance surface rather than one bit.
    let membership = room
        .identity
        .issue_membership(&req.member_did)
        .await
        .map_err(Refusal::internal)?;
    let authority = room
        .identity
        .issue_authority(
            &req.member_did,
            &room
                .member_actions
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )
        .await
        .map_err(Refusal::internal)?;

    // The commit advanced the epoch, so the host has to be told before the new member can
    // write anything: a record is sealed under the epoch current when it was written, and a
    // host refuses ciphertext bound to an epoch it does not know about.
    crate::mint_epoch(&host_url, &demo.owner, room, epoch, link.as_ref())
        .await
        .map_err(|e| Refusal::new("e.p.msg.internal-error", e))?;

    Ok(Admitted {
        room_id: room.id.clone(),
        room_did: room.identity.did.clone(),
        welcome: B64.encode(welcome),
        epoch,
        membership: serde_json::from_str(&membership)
            .map_err(|e| Refusal::internal(e.to_string()))?,
        authority: serde_json::from_str(&authority)
            .map_err(|e| Refusal::internal(e.to_string()))?,
        steps: vec![
            "invitation verified — issued by this room, to you, unspent".into(),
            "key package validated against the room's ciphersuite".into(),
            format!("member added — the group committed to epoch {epoch}"),
            "welcome sealed to that key package alone".into(),
            "membership credential issued".into(),
            format!(
                "authority credential issued — {}",
                room.member_actions.join(", ")
            ),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A member's room key, and the `did:key` naming it.
    struct TestKey {
        did: String,
        secret: affinidi_secrets_resolver::secrets::Secret,
    }

    fn mint() -> TestKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(&public);
        let did = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &multicodec)
        );
        let secret = affinidi_secrets_resolver::secrets::Secret::from_str(
            &format!("{did}#{}", &did["did:key:".len()..]),
            &serde_json::json!({
                "crv": "Ed25519",
                "d": B64.encode(signing.to_bytes()),
                "kty": "OKP",
                "x": B64.encode(public),
            }),
        )
        .unwrap();
        TestKey { did, secret }
    }

    /// Sign a request as `key` — what a member's wasm does before it goes on the wire.
    async fn signed(key: &TestKey, transport_did: &str) -> serde_json::Value {
        let mut doc = serde_json::to_value(AdmissionRequest {
            room_did: "did:key:z6MkroomWouldGoHere".into(),
            member_did: key.did.clone(),
            transport_did: transport_did.into(),
            key_package: None,
            invitation: None,
            since_epoch: None,
        })
        .unwrap();
        let proof = affinidi_data_integrity::DataIntegrityProof::sign(
            &doc,
            &key.secret,
            affinidi_data_integrity::SignOptions::new(),
        )
        .await
        .unwrap();
        doc.as_object_mut()
            .unwrap()
            .insert("proof".into(), serde_json::to_value(&proof).unwrap());
        doc
    }

    #[tokio::test]
    async fn a_request_signed_by_its_member_and_sent_from_its_transport_is_accepted() {
        let key = mint();
        let body = signed(&key, "did:peer:2.transport").await;

        let req = verify_request(&body, Some("did:peer:2.transport"))
            .await
            .expect("the happy path must pass, or every refusal below proves nothing");
        assert_eq!(req.member_did, key.did);
    }

    /// **The binding, and the reason it is here.** A signed request is a standing artefact.
    /// Without this clause anybody who ever saw one could send it from their own transport
    /// identity and have the room's reply — the VIC — delivered to them instead. The
    /// signature still verifies; it simply stops being about the connection carrying it.
    #[tokio::test]
    async fn a_request_replayed_from_another_connection_is_refused() {
        let key = mint();
        let body = signed(&key, "did:peer:2.the-member").await;

        let refusal = verify_request(&body, Some("did:peer:2.somebody-else"))
            .await
            .expect_err("a signed request is not a bearer token");
        assert_eq!(refusal.code, "e.p.msg.unauthorized");
        assert!(
            refusal.message.contains("bearer token"),
            "the refusal should say why: {}",
            refusal.message
        );
    }

    /// A proof that verifies only means *somebody* signed it. Without this clause an
    /// attacker names any member they like and signs with their own key.
    #[tokio::test]
    async fn a_request_naming_one_member_and_signed_by_another_is_refused() {
        let signer = mint();
        let victim = mint();
        let mut body = signed(&signer, "did:peer:2.transport").await;
        body["memberDid"] = serde_json::Value::String(victim.did.clone());

        let refusal = verify_request(&body, Some("did:peer:2.transport"))
            .await
            .expect_err("naming a member you cannot sign for must not work");
        assert_eq!(refusal.code, "e.p.msg.unauthorized");
    }

    /// The proof covers the body, so changing the body after signing must break it. Asserted
    /// rather than assumed: the check that removes `proof` before verifying is the one place
    /// a mistake would silently verify a *different* document from the one that arrived.
    #[tokio::test]
    async fn a_request_altered_after_signing_is_refused() {
        let key = mint();
        let mut body = signed(&key, "did:peer:2.transport").await;
        body["roomDid"] = serde_json::Value::String("did:key:z6MkSomeOtherRoom".into());

        let refusal = verify_request(&body, Some("did:peer:2.transport"))
            .await
            .expect_err("an altered request must not verify");
        assert_eq!(refusal.code, "e.p.msg.unauthorized");
    }

    #[tokio::test]
    async fn a_request_with_no_proof_is_refused() {
        let mut body = serde_json::to_value(AdmissionRequest {
            room_did: "did:key:z6MkRoom".into(),
            member_did: "did:key:z6MkMember".into(),
            transport_did: "did:peer:2.transport".into(),
            key_package: None,
            invitation: None,
            since_epoch: None,
        })
        .unwrap();
        body.as_object_mut().unwrap().remove("proof");

        let refusal = verify_request(&body, Some("did:peer:2.transport"))
            .await
            .expect_err("an unsigned request proves nothing about the room key");
        assert_eq!(refusal.code, "e.p.msg.bad-request");
    }

    /// Over HTTP there is no authenticated transport identity, so the binding cannot be
    /// checked — and this asserts that the *proof* still is. A carrier that could not check
    /// one thing must not quietly stop checking the other.
    #[tokio::test]
    async fn without_a_sender_the_proof_is_still_required() {
        let signer = mint();
        let victim = mint();
        let mut body = signed(&signer, "did:peer:2.transport").await;
        body["memberDid"] = serde_json::Value::String(victim.did);

        let refusal = verify_request(&body, None)
            .await
            .expect_err("no transport identity is not no checks");
        assert_eq!(refusal.code, "e.p.msg.unauthorized");
    }
}
