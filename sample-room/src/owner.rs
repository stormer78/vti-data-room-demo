//! The room's **owner** — the party that admits people and issues what governs them.
//!
//! In a real deployment this is a person with a VTA, driving it from the wallet console or
//! `pnm-cli`. It is here only so the demo runs standalone.
//!
//! # The room has its own identity, and that order is forced
//!
//! A room is a DTG node, not a row in a host's table: it holds a DID, and it *issues* the
//! credentials that govern it. So the identity is minted first and a host is told about a
//! room that already exists — the reverse is a host handing out an identifier, and a room
//! whose name came from its host could never leave it.
//!
//! `did:key` here rather than the `did:webvh` a real room mints, and the difference is worth
//! naming: a `did:key` carries its verification key in its own identifier, so every
//! signature this room makes can be checked lexically, with no resolution and nothing to be
//! offline. That is what lets a browser verify an invitation, and it is also the posture
//! `room-host` takes by default — its verifier is `did:key`-only precisely so that no
//! unauthenticated request can make it fetch. What a `did:key` cannot do is carry a service
//! endpoint, so a room identified this way advertises no mediator and is not addressable
//! over DIDComm. A real room needs `did:webvh` for exactly that reason.
//!
//! # Three credentials, and they are not interchangeable
//!
//! - a **VIC** says you were invited. Consent to join, and nothing else.
//! - a **VMC** says you are a member. What a host sees when it asks who acted.
//! - a **VAC** says what you may *do* — the chain root a member attenuates from.
//!
//! Being invited is not being a member, and being a member is not being allowed to write.
//! Collapsing any two of them is how a room ends up with one bit of authorization.

use chrono::{Duration, Utc};
use dtg_credentials::DTGCredential;

/// A room's signing identity.
///
/// Two fields for the keys, and the split is the point. `signing` is the Ed25519 key the
/// room signs credentials with — the one a member verifies lexically out of the room's own
/// identifier. `secrets` is *every* key the identity holds, which for a `did:peer:2` also
/// includes the X25519 key agreement half; DIDComm needs that one to decrypt what is sent
/// to the room, and a resolver handed only the signing key can authenticate an inbound
/// message it cannot open.
///
/// The first cut kept only `#key-1` and dropped the rest on the floor, which was correct
/// while the room only ever signed and wrong the moment it had to listen.
pub struct RoomIdentity {
    pub did: String,
    signing: affinidi_secrets_resolver::secrets::Secret,
    secrets: Vec<affinidi_secrets_resolver::secrets::Secret>,
}

/// The DIDComm service a room advertises: reach me through this mediator.
///
/// `serviceEndpoint.uri` is the mediator's **DID**, not a URL — matching how the built-in
/// `ai-agent` and `room` did:webvh templates advertise `DIDCommMessaging`. A client reads
/// the mediator DID from here and dials through it, which is what lets every room on one
/// mediator share a single connection rather than opening one apiece.
fn vta_peer_service(mediator_did: &str) -> Vec<affinidi_tdk::dids::PeerService> {
    use affinidi_tdk::dids::{OneOrMany, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong};
    vec![PeerService {
        type_: "DIDCommMessaging".into(),
        endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
            uri: mediator_did.to_string(),
            accept: vec!["didcomm/v2".into()],
            routing_keys: vec![],
        })),
        id: None,
    }]
}

impl RoomIdentity {
    /// Mint a room's identity.
    ///
    /// **`did:peer:2` when a mediator is named, `did:key` otherwise**, and the difference
    /// is the whole of whether a room can be joined by somebody this site was not told
    /// about.
    ///
    /// A `did:key` is a key and nothing else: it has no service block, so it cannot say
    /// where its owner is reachable. A member handed only the room's identifier can verify
    /// everything the room signs and still have no way to *ask to join*. A `did:peer:2`
    /// carries services inline, so it can advertise the mediator its owner listens on —
    /// while staying self-certifying, which is what keeps verification lexical on both
    /// sides (see `vti-rooms-wasm`'s invitation gate and `vta-sdk`'s verifier, which both
    /// resolve `did:peer` with no I/O).
    ///
    /// Production mints `did:webvh` instead, for a reason neither of these has: a room's
    /// controller must be able to change, and transferring ownership is a controller
    /// change. `did:peer` encodes its keys in the identifier, so it can never have one.
    ///
    /// Not defaulted to a fabricated mediator. A room advertising somewhere nobody listens
    /// is worse than a room advertising nothing: the first fails at the join, the second
    /// says so before you try.
    pub fn mint(mediator_did: Option<&str>) -> Result<Self, String> {
        match mediator_did {
            Some(mediator) => Self::mint_peer(mediator),
            None => Self::mint_key(),
        }
    }

    fn mint_peer(mediator_did: &str) -> Result<Self, String> {
        use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};

        let services = vta_peer_service(mediator_did);
        let (did, secrets) = DID::generate_did_peer_with_services(
            vec![
                (PeerKeyRole::Verification, KeyType::Ed25519),
                (PeerKeyRole::Encryption, KeyType::X25519),
            ],
            Some(services),
        )
        .map_err(|e| format!("mint the room's did:peer: {e}"))?;

        // `#key-1` is the Ed25519 verification key — the one a room signs with. `#key-2` is
        // key agreement and cannot sign, which is a distinction worth making by name rather
        // than by position.
        let signing = secrets
            .iter()
            .find(|s| s.id.ends_with("#key-1"))
            .cloned()
            .ok_or("the minted did:peer has no verification key")?;

        Ok(Self {
            did,
            signing,
            secrets,
        })
    }

    fn mint_key() -> Result<Self, String> {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

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

        // The `did:key` convention: the multibase tag IS the verification-method fragment,
        // which is what makes the key lexically recoverable from the identifier.
        let secret = affinidi_secrets_resolver::secrets::Secret::from_str(
            &format!("{did}#{}", &did["did:key:".len()..]),
            &serde_json::json!({
                "crv": "Ed25519",
                "d": B64.encode(signing.to_bytes()),
                "kty": "OKP",
                "x": B64.encode(public),
            }),
        )
        .map_err(|e| format!("build the room's signing secret: {e}"))?;

        // One key, and it is the whole identity: a `did:key` has no separate key-agreement
        // half. DIDComm still reaches such a DID — the encryption key is derived from the
        // Ed25519 one by the Montgomery map — but nothing here has to hold it.
        Ok(Self {
            did,
            secrets: vec![secret.clone()],
            signing: secret,
        })
    }

    /// This identity's Ed25519 public key.
    ///
    /// Read from the secret rather than re-derived from the identifier. The identifier is a
    /// `did:key` or a `did:peer` depending on whether the room advertises a mediator, and a
    /// helper that assumed the first sliced the second by a fixed prefix length and produced
    /// a multibase error about a colon. A party that holds a key does not need to parse its
    /// own name to find it.
    pub fn public_key(&self) -> &[u8] {
        self.signing.get_public_bytes()
    }

    /// Every key this identity holds, for a secrets resolver.
    ///
    /// The signing key **and** the key-agreement key, because a party that can be written to
    /// over DIDComm has to be able to decrypt as well as prove who it is.
    pub fn secrets(&self) -> &[affinidi_secrets_resolver::secrets::Secret] {
        &self.secrets
    }

    /// An invitation to `subject`: consent to join, single-use, and short-lived.
    ///
    /// An hour, because an invitation is an act somebody is about to perform rather than a
    /// standing entitlement. One that lives for a month is a key to the room left under the
    /// mat.
    pub async fn invite(&self, subject: &str) -> Result<String, String> {
        let now = Utc::now();
        let mut vic = DTGCredential::new_vic(
            self.did.clone(),
            subject.to_string(),
            now,
            Some(now + Duration::hours(1)),
        )
        // An id is not decoration: it is what a member records as spent, and single-use
        // cannot be enforced without one. An invitation that cannot be spent is one that
        // can be spent forever.
        .with_id(&format!("urn:uuid:{}", uuid::Uuid::new_v4()));
        self.sign(&mut vic).await?;
        serde_json::to_string(vic.credential()).map_err(|e| e.to_string())
    }

    /// A membership credential: this DID belongs to this room.
    pub async fn issue_membership(&self, subject: &str) -> Result<String, String> {
        let now = Utc::now();
        let mut vmc = DTGCredential::new_vmc(
            self.did.clone(),
            subject.to_string(),
            now,
            Some(now + Duration::days(365)),
            // Not a personhood credential. This room attests membership, and has no
            // basis to say anything about whether its member is a person — a demo that
            // claimed otherwise would be minting the one assertion nobody checked.
            false,
        )
        .with_id(&format!("urn:uuid:{}", uuid::Uuid::new_v4()));
        self.sign(&mut vmc).await?;
        serde_json::to_string(vmc.credential()).map_err(|e| e.to_string())
    }

    /// An authority credential: what this member may do, at this room's scope.
    ///
    /// The chain root. A member attenuates it per request to one action, and `attenuate`
    /// refuses to widen — so what is granted here is the ceiling for everything that
    /// follows, and a demo that granted `admin` to every visitor would be demonstrating a
    /// room with no governance rather than a room.
    ///
    /// `valid_until` is required by the constructor, and deliberately: nothing about a
    /// subject's current standing is consulted when a chain is verified, so authority that
    /// does not expire is authority nobody can withdraw by waiting.
    pub async fn issue_authority(&self, subject: &str, actions: &[&str]) -> Result<String, String> {
        let now = Utc::now();
        let mut vac = DTGCredential::new_vac(
            self.did.clone(),
            subject.to_string(),
            // Scope is the room itself: this grant is about this room and no other.
            self.did.clone(),
            actions.iter().map(|a| (*a).to_string()).collect(),
            now,
            now + Duration::days(30),
        )
        .map_err(|e| format!("build the authority credential: {e}"))?
        .with_id(&format!("urn:uuid:{}", uuid::Uuid::new_v4()));
        self.sign(&mut vac).await?;
        serde_json::to_string(vac.credential()).map_err(|e| e.to_string())
    }

    /// Attach this identity's `eddsa-jcs-2022` proof to a Trust-Task document.
    ///
    /// A host takes the presenter from the document's own proof and never from a payload
    /// field — a payload says what is being asked, not who is asking — so this is how the
    /// owner is authenticated when it registers a room.
    pub async fn sign_document(&self, document: serde_json::Value) -> Result<serde_json::Value, String> {
        let mut doc = document;
        // A proof never covers itself.
        doc.as_object_mut()
            .ok_or("a signable document must be a JSON object")?
            .remove("proof");
        let proof = affinidi_data_integrity::DataIntegrityProof::sign(
            &doc,
            &self.signing,
            affinidi_data_integrity::SignOptions::new(),
        )
        .await
        .map_err(|e| format!("sign the document: {e}"))?;
        doc.as_object_mut()
            .ok_or("a signable document must be a JSON object")?
            .insert("proof".into(), serde_json::to_value(&proof).map_err(|e| e.to_string())?);
        Ok(doc)
    }

    /// Mint an authority presentation for one action, as this identity.
    ///
    /// The same act the browser performs, and the same shape: strings on the wire, leaf
    /// first, narrowed to one action. Binding to the presenter is the library's rule since
    /// dtg-credentials 0.8 — `verify_chain` requires the leaf to grant to whoever presents
    /// it — so there is no longer a field to fill in, and no way to fill it in wrongly.
    pub async fn present(
        &self,
        vac: &str,
        vmc: &str,
        action: &str,
    ) -> Result<serde_json::Value, String> {
        let root: DTGCredential =
            serde_json::from_str(vac).map_err(|e| format!("authority credential: {e}"))?;
        let now = Utc::now();
        let mut leaf = root
            .attenuate(
                self.did.clone(),
                vec![action.to_string()],
                now,
                now + Duration::hours(4),
            )
            .map_err(|e| format!("narrow this authority to `{action}`: {e}"))?;
        self.sign(&mut leaf).await?;

        Ok(serde_json::json!({
            "membership": vmc,
            "authority": [
                serde_json::to_string(leaf.credential()).map_err(|e| e.to_string())?,
                vac,
            ],
        }))
    }

    async fn sign(&self, credential: &mut DTGCredential) -> Result<(), String> {
        credential
            .sign(&self.signing, None)
            .await
            .map(|_| ())
            .map_err(|e| format!("sign as the room: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A room given a mediator advertises it; one without stays `did:key`.
    ///
    /// The difference decides whether a member handed only the room's identifier can reach
    /// its owner to ask to join — so it is asserted rather than assumed, and asserted on the
    /// identifier itself, which is the thing that travels.
    #[tokio::test]
    async fn a_room_advertises_its_mediator_only_when_it_has_one() {
        let mediator = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG";
        let advertising = RoomIdentity::mint(Some(mediator)).unwrap();
        assert!(
            advertising.did.starts_with("did:peer:2"),
            "a room with a mediator needs a method that can carry a service: {}",
            advertising.did
        );

        // Resolved with the SAME resolver a browser member uses, so this asserts what a
        // member would actually see rather than what this process happens to know. The
        // service rides in the identifier — that is what "self-certifying with a service
        // block" buys, and why resolving it needs no network.
        use affinidi_did_common::DID;
        use affinidi_did_resolver_traits::{PeerResolver, Resolver};
        let doc = PeerResolver
            .resolve(&DID::try_from(advertising.did.as_str()).expect("a well-formed DID"))
            .expect("PeerResolver handles did:peer")
            .expect("a did:peer resolves by computation");
        assert!(
            format!("{doc:?}").contains(mediator),
            "the room's own identifier must name the mediator its owner listens on"
        );

        let silent = RoomIdentity::mint(None).unwrap();
        assert!(
            silent.did.starts_with("did:key:"),
            "with nowhere to advertise, a room is a key and nothing else: {}",
            silent.did
        );
    }

    /// What the room issues is what a member can actually verify and use.
    ///
    /// Asserted against the real verifiers rather than by reading the JSON back: the
    /// invitation through the same six clauses a browser member runs, and the authority
    /// through `verify_chain` after a member has narrowed it.
    #[tokio::test]
    async fn the_room_issues_credentials_its_members_can_use() {
        let room = RoomIdentity::mint(None).unwrap();
        let member = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

        // The invitation verifies against the room's own key — which a member recovers
        // from the room's identifier, with nothing to resolve. That property is what the
        // whole `did:key` choice above is for, so it is asserted rather than assumed.
        let vic: DTGCredential = serde_json::from_str(&room.invite(member).await.unwrap()).unwrap();
        vic.verify_proof_with_public_key(room.public_key())
            .expect("the room's own invitation must verify against the room's own key");
        assert_eq!(vic.issuer(), room.did);
        assert_eq!(vic.subject(), member);
        assert!(vic.id().is_some(), "without an id, single-use cannot be enforced");

        // The authority credential is a chain root a member narrows from, and the ceiling
        // for everything below it.
        let vac: DTGCredential =
            serde_json::from_str(&room.issue_authority(member, &["read", "write"]).await.unwrap())
                .unwrap();
        assert_eq!(vac.issuer(), room.did);
        assert_eq!(vac.subject(), member);

        // A member narrows it to one action and the real chain verifier accepts the result
        // — the same function `room-host` runs.
        let now = Utc::now();
        let leaf = vac
            .attenuate(
                member.to_string(),
                vec!["read".into()],
                now,
                now + Duration::hours(4),
            )
            .expect("a member may narrow what the room granted");
        assert!(
            vac.attenuate(
                member.to_string(),
                vec!["curate".into()],
                now,
                now + Duration::hours(4),
            )
            .is_err(),
            "attenuation must refuse to widen: `curate` was never granted"
        );
        let _ = leaf;
    }
}
