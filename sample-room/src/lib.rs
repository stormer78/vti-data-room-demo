//! The **admission protocol** — the only thing a room's owner and a would-be member both
//! have to agree about.
//!
//! It is a library rather than a module because two different parties speak it, and a
//! protocol defined inside one of them is a protocol the other is guessing at. `main.rs` is
//! the owner; `src/bin/join-by-did.rs` is a member who knows nothing but a room's DID. Both
//! link this.
//!
//! # Why this is not a Trust Task
//!
//! `rooms/owner/{invite,issue-membership,issue-authority}` are real Trust Tasks, and an
//! owner answering these messages performs all three. But a Trust Task is an instruction
//! **you give your own agent**, authorised by your control of it — `vta-service` gates those
//! three on `CredentialWrite` and never asks who the subject is. What travels here is the
//! opposite: a stranger asking an owner to *decide* something. Dressing that up as a Trust
//! Task would say the stranger may instruct the room's agent, which is exactly the thing
//! that must not be true.
//!
//! So this is a plain DIDComm protocol in the demo's own namespace. What the owner decides
//! *with* is Trust-Task machinery.
//!
//! # Two identities, and the binding between them
//!
//! A browser member holds two keys and they are not interchangeable:
//!
//! - a **transport identity** (`did:peer:2`) — how the mediator addresses them, and what
//!   DIDComm's authcrypt proves;
//! - a **room identity** (`did:key`) — what the room's credentials name, and what signs
//!   every document the host later authenticates them by.
//!
//! The room identity has to be the VIC's subject, because it is the key that will sign
//! records. But it is not what sent the message. So a request carries **both proofs** and
//! the owner checks that they agree:
//!
//! 1. DIDComm authcrypt proves the *transport* DID sent this.
//! 2. An `eddsa-jcs-2022` proof inside the body proves the *room* DID authored it.
//! 3. The body names the transport DID, binding the two together.
//!
//! Drop (3) and the protocol breaks in a way that is easy to miss. A signed request is a
//! standing artefact: anybody who ever saw one could replay it from their own transport
//! identity and have the room's reply delivered to them instead. The signature would still
//! verify — it just would no longer be about the connection carrying it.

use serde::{Deserialize, Serialize};

/// The protocol these messages belong to. Namespaced to the demo — see the module docs.
pub const PROTOCOL: &str = "https://dataroom.demo/admission/0.1";

/// Member → owner: "here is my DID, may I join?"
pub const REQUEST_INVITATION: &str = "https://dataroom.demo/admission/0.1/request-invitation";
/// Owner → member: the VIC.
pub const INVITATION: &str = "https://dataroom.demo/admission/0.1/invitation";
/// Member → owner: "here is that VIC and my key package, admit me."
pub const REQUEST_ADMISSION: &str = "https://dataroom.demo/admission/0.1/request-admission";
/// Owner → member: the Welcome, and what governs them.
pub const ADMITTED: &str = "https://dataroom.demo/admission/0.1/admitted";

/// The body of either request, before its proof is checked.
///
/// One shape for both, because both answer the same three questions — which room, who is
/// asking, and over which connection — and only the second carries anything more.
/// `Debug`, because everything in it is public: two identifiers, a KeyPackage (which is
/// published by design) and a credential somebody else signed. [`Admitted`] deliberately has
/// none — it carries a Welcome, and a Welcome is the group's secrets sealed to one joiner.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionRequest {
    /// The room's DID. Named by the asker rather than inferred from the connection: one
    /// owner listens for several rooms on one mediator, so the message has to say which.
    pub room_did: String,
    /// The **room identity** — what the credentials will name, and what signed this.
    pub member_did: String,
    /// The **transport identity** — what DIDComm delivered this from. Checked against the
    /// authenticated sender, which is what stops a signed request being replayed by
    /// somebody else.
    pub transport_did: String,
    /// The member's KeyPackage, base64url. Only the admission request carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_package: Option<String>,
    /// The invitation being presented. Only the admission request carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation: Option<serde_json::Value>,
}

/// What admission produces.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Admitted {
    pub room_id: String,
    pub room_did: String,
    /// The Welcome, base64url. Sealed to the KeyPackage presented and to nothing else.
    pub welcome: String,
    /// The room's epoch after the commit this admission produced.
    pub epoch: u32,
    /// The room's attestation that this DID belongs to it.
    pub membership: serde_json::Value,
    /// What this member may do — the chain root they attenuate from, per request.
    pub authority: serde_json::Value,
    /// Each step the owner took, so a member sees the ceremony rather than a spinner.
    pub steps: Vec<String>,
}

/// What a room advertises: where its owner listens, and over what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertised {
    /// The mediator's DID.
    pub mediator: String,
    /// Whether the room says it serves TSP there.
    pub tsp: bool,
    /// Whether the room says it serves DIDComm there.
    pub didcomm: bool,
}

impl Advertised {
    /// The carrier to use: **TSP if offered, DIDComm otherwise.**
    ///
    /// Chosen from what the room says rather than from what happens to work. A mediator
    /// carries both on one socket, so a client that always spoke TSP would usually succeed —
    /// and would break, with nothing in the room's document having changed, the first time
    /// it met an owner that only served DIDComm.
    pub fn preferred(&self) -> Option<&'static str> {
        match (self.tsp, self.didcomm) {
            (true, _) => Some("tsp"),
            (false, true) => Some("didcomm"),
            (false, false) => None,
        }
    }
}

/// Read a room's own identifier for where its owner listens, and over what.
///
/// **This is the lookup that makes a room addressable.** A member holds an identifier and
/// nothing else; reading the service block out of it is how they find the party that can
/// admit them. `did:peer` resolution is pure computation, so this costs no network and
/// works offline — the property that let the room be a `did:peer` rather than something
/// that needs a registry.
///
/// `serviceEndpoint.uri` is the mediator's **DID**, not a URL, matching how the `ai-agent`
/// and `room` `did:webvh` templates advertise `DIDCommMessaging`. A client dials the
/// mediator by DID, which is what lets every room on one mediator share a connection.
///
/// `None` when the room advertises nothing — a `did:key` room, which can be verified but
/// not reached.
pub fn advertised_mediator(room_did: &str) -> Result<Option<Advertised>, String> {
    use affinidi_did_common::DID;
    use affinidi_did_resolver_traits::{PeerResolver, Resolver};

    if !room_did.starts_with("did:peer:") {
        return Ok(None);
    }

    let parsed =
        DID::try_from(room_did).map_err(|e| format!("`{room_did}` is not a well-formed DID: {e}"))?;
    let doc = PeerResolver
        .resolve(&parsed)
        .ok_or_else(|| format!("`{room_did}` is not a did:peer this build resolves"))?
        .map_err(|e| format!("`{room_did}` did not resolve: {e}"))?;

    let mut found: Option<Advertised> = None;
    for service in &doc.service {
        // `dm` is the did:peer abbreviation for `DIDCommMessaging`; a resolver may expand it
        // or leave it, so both spellings mean the same service.
        let didcomm = service
            .type_
            .iter()
            .any(|t| t == "DIDCommMessaging" || t == "dm");
        let tsp = service.type_.iter().any(|t| t == "TSPTransport");
        if !didcomm && !tsp {
            continue;
        }
        let Some(uri) = endpoint_uri(&service.service_endpoint) else {
            continue;
        };

        match &mut found {
            // One mediator per room. A second service naming a different one would mean two
            // places to ask, and nothing says which answers — so the first is taken and the
            // rest are only read for which carriers they add.
            Some(a) if a.mediator == uri => {
                a.tsp |= tsp;
                a.didcomm |= didcomm;
            }
            Some(_) => continue,
            None => {
                found = Some(Advertised {
                    mediator: uri,
                    tsp,
                    didcomm,
                })
            }
        }
    }
    Ok(found)
}

/// Pull the endpoint URI out of a service block, whichever of the several shapes the
/// specification allows it happens to be in.
///
/// Hand-written rather than `Endpoint::get_uri`, and not by preference: that helper returns
/// `Value::to_string()` for the map and array forms, which for a JSON string **keeps the
/// quotes** — so a `did:peer` service block yields `"\"did:webvh:…\""` while the plain-URL
/// form yields the bare value. Dialling the quoted one fails as an unresolvable DID, which
/// reads like a bad service block rather than like a helper that stringified a `Value`.
/// Worth fixing in `affinidi-did-common`; until then, extracted here.
fn endpoint_uri(endpoint: &affinidi_did_common::service::Endpoint) -> Option<String> {
    use affinidi_did_common::service::Endpoint;
    match endpoint {
        Endpoint::Url(url) => Some(url.to_string()),
        Endpoint::Map(value) => from_json(value),
        // `Endpoint` is `#[non_exhaustive]`: a shape this build has never seen is a service
        // block it cannot dial, which is not the same as one that advertises nothing — but
        // from a caller's side both mean "no address here", and pretending otherwise would
        // return an endpoint invented locally.
        _ => None,
    }
}

fn from_json(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => o.get("uri").and_then(from_json),
        serde_json::Value::Array(a) => a.iter().find_map(from_json),
        _ => None,
    }
}
