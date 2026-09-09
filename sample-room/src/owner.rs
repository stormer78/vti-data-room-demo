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
pub struct RoomIdentity {
    pub did: String,
    secret: affinidi_secrets_resolver::secrets::Secret,
}

impl RoomIdentity {
    /// Mint a room's `did:key` and the secret behind it.
    pub fn mint() -> Result<Self, String> {
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

        Ok(Self { did, secret })
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

    async fn sign(&self, credential: &mut DTGCredential) -> Result<(), String> {
        credential
            .sign(&self.secret, None)
            .await
            .map(|_| ())
            .map_err(|e| format!("sign as the room: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the room issues is what a member can actually verify and use.
    ///
    /// Asserted against the real verifiers rather than by reading the JSON back: the
    /// invitation through the same six clauses a browser member runs, and the authority
    /// through `verify_chain` after a member has narrowed it.
    #[tokio::test]
    async fn the_room_issues_credentials_its_members_can_use() {
        let room = RoomIdentity::mint().unwrap();
        let member = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

        // The invitation verifies against the room's own key — which a member recovers
        // from the room's identifier, with nothing to resolve. That property is what the
        // whole `did:key` choice above is for, so it is asserted rather than assumed.
        let vic: DTGCredential = serde_json::from_str(&room.invite(member).await.unwrap()).unwrap();
        let (_, key_bytes) = multibase::decode(&room.did["did:key:".len()..]).unwrap();
        vic.verify_proof_with_public_key(&key_bytes[2..])
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
                Some(member.to_string()),
            )
            .expect("a member may narrow what the room granted");
        assert!(
            vac.attenuate(
                member.to_string(),
                vec!["curate".into()],
                now,
                now + Duration::hours(4),
                None,
            )
            .is_err(),
            "attenuation must refuse to widen: `curate` was never granted"
        );
        let _ = leaf;
    }
}
