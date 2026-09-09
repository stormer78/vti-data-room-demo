//! Join a room knowing **nothing but its DID**.
//!
//! ```text
//! cargo run --bin join-by-did -- did:peer:2.Vz6Mk…                    # join
//! cargo run --bin join-by-did -- --tsp did:peer:2.Vz6Mk…              # force TSP
//! cargo run --bin join-by-did -- <roomDid> --at did:peer:2.Vz6Mk…     # and write a record
//! ```
//!
//! `--at` is the **host**, and it has to be said because a room's identifier deliberately
//! does not name one: a room may be served by several, and a room that named its host could
//! never move. With it, this joins and then seals, writes, lists and re-opens a record — the
//! whole member surface, none of it over HTTP.
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

/// The DIDComm `type` a Trust-Task envelope rides under, per the framework binding.
const TRUST_TASK_ENVELOPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";
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
    let host = args
        .iter()
        .position(|a| a == "--at")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let room_did = args
        .iter()
        .enumerate()
        // Skip flags and the value that follows `--at`.
        .filter(|(i, a)| {
            !a.starts_with("--") && args.get(i.wrapping_sub(1)).map(String::as_str) != Some("--at")
        })
        .map(|(_, a)| a.clone())
        .next()
        .ok_or("usage: join-by-did [--tsp] <room did:peer> [--at <host did>]")?;

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
    let client = Client::connect(
        &mediator,
        &transport_did,
        transport_secrets,
        carrier == "tsp",
    )
    .await?;

    // 3. Ask.
    let request = member
        .sign(&wire::AdmissionRequest {
            room_did: room_did.clone(),
            member_did: member.did.clone(),
            transport_did: transport_did.clone(),
            key_package: None,
            invitation: None,
            since_epoch: None,
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
    println!(
        "invitation verified — issued by this room, to this key, in window, signed by the room"
    );

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
            since_epoch: None,
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
    let mut room = vti_rooms::sealed::SealedRoom::new(room_did.clone(), group);

    println!(
        "\njoined `{}` at epoch {}",
        admitted.room_id, admitted.epoch
    );
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

    // 7. And, if we were told where the records live, use them.
    let Some(host) = host else {
        println!(
            "\n(no --at, so nothing was read or written — a room's identifier does not name \
             its host, so somebody has to say which one)"
        );
        return Ok(());
    };
    let held = Membership {
        host: &host,
        room_did: &room_did,
        member: &member,
        admitted: &admitted,
    };
    records(&client, &held, &mut room).await
}

/// Seal a record, write it, list the room, and open what comes back.
///
/// The whole member surface, over the same link the join went through and not a URL in it.
/// What proves the host is doing its job is the **opening**: the record is sealed in this
/// process under a key the host has never held, so a host that changed a byte — or relocated
/// the record to another key, version or epoch — produces something that does not open rather
/// than something wrong.
async fn records(
    client: &Client,
    held: &Membership<'_>,
    room: &mut vti_rooms::sealed::SealedRoom,
) -> Result<(), String> {
    let key = format!("cli/{}", uuid::Uuid::new_v4());
    println!("\nhost      {}", held.host);

    // Versions are monotonic **per room**, not per record, and the version is bound into the
    // ciphertext — so it is asked for rather than assumed. Sealing against a guess stores
    // fine and never opens, which reads as corruption.
    let listed = client
        .host_task(
            held,
            "https://trusttasks.org/spec/rooms/records/list/0.1",
            "read",
            serde_json::json!({}),
        )
        .await?;
    let existing = listed["records"].as_array().cloned().unwrap_or_default();
    let next_version = existing
        .iter()
        .filter_map(|r| r["version"].as_u64())
        .max()
        .unwrap_or(0)
        + 1;
    println!("records   {} already stored", existing.len());

    let plaintext = b"Written by join-by-did, over a mediator.";
    let sealed = room
        .seal_record(&key, next_version, plaintext)
        .map_err(|e| format!("seal the record: {e}"))?;

    client
        .host_task(
            held,
            "https://trusttasks.org/spec/rooms/records/put/0.1",
            // `write`, not `read`: the presentation is narrowed to exactly this action, and a
            // member holding only `read` is refused by their own `attenuate` first.
            "write",
            serde_json::json!({
                "key": key,
                "sealed": sealed,
                // Create-only. This is about the *key*, where the number sealed above is
                // about the room — two questions both spelled as a version.
                "expectedVersion": 0,
            }),
        )
        .await?;
    println!("wrote     {key} at version {next_version}");

    let got = client
        .host_task(
            held,
            "https://trusttasks.org/spec/rooms/records/get/0.1",
            "read",
            serde_json::json!({ "key": key }),
        )
        .await?;
    // A stored record comes back **flat** — `sealed` is the ciphertext, with `nonce` and
    // `epoch` beside it — while `put` takes the same three as one `SealedContent`. Opening
    // needs all three together, and the epoch is the one that decides which key is used, so
    // they are reassembled here. The browser member does exactly this, and for the same
    // reason; the asymmetry is the host's wire form, not either client's choice.
    // `sealed` is a `SealedContent` — the shape the schema always specified.
    //
    // This used to reassemble it from flat `sealed`/`nonce`/`epoch` members, because that is
    // what a host actually sent: both hosts answered a read by serialising the *storage*
    // record, where `sealed` is a bare base64 string. #1368 gave the task a response type and
    // the workaround became the bug — a client written against the defect breaks the moment
    // the defect is fixed, which is the argument for fixing rather than accommodating.
    let stored: vti_rooms::wire::SealedContent = serde_json::from_value(got["sealed"].clone())
        .map_err(|e| format!("the host's record: {e}"))?;

    let opened = room
        .open_record(&key, next_version, &stored)
        .map_err(|e| format!("open the record: {e}"))?;

    println!(
        "read back {}",
        String::from_utf8(opened).map_err(|e| e.to_string())?
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

    /// Mint an authority presentation for one action on this room.
    ///
    /// Derived from the room's own grant by `attenuate`, which refuses to widen — so asking
    /// for an action this member does not hold fails **here**, in their own hands, rather
    /// than as a refusal from the host. "You were never given this" and "the host disagreed"
    /// are different sentences, and only the first can be answered by asking the owner.
    ///
    /// No `audience`: dtg-credentials 0.8 removed the field and requires the presenter to be
    /// the leaf's subject instead. The leaf grants to this member and a verifier accepts it
    /// from nobody else, so the binding is the library's rule rather than a value to fill in
    /// — which is what it had to become, because filled with a *host's* DID it named a party
    /// no presenter could match and every request was refused.
    async fn present(
        &self,
        authority: &serde_json::Value,
        membership: &serde_json::Value,
        action: &str,
    ) -> Result<serde_json::Value, String> {
        use dtg_credentials::DTGCredential;

        let root: DTGCredential = serde_json::from_value(authority.clone())
            .map_err(|e| format!("authority credential: {e}"))?;
        let now = chrono::Utc::now();
        let mut leaf = root
            .attenuate(
                self.did.clone(),
                vec![action.to_string()],
                now,
                // Required, and rightly: a presentation that does not expire is a standing
                // grant, which is the one thing a presentation exists not to be.
                now + chrono::Duration::hours(4),
            )
            .map_err(|e| format!("cannot narrow your authority to `{action}`: {e}"))?;
        leaf.sign(&self.secret, None)
            .await
            .map_err(|e| format!("sign the attenuated credential: {e}"))?;

        // **Strings, not objects.** `AuthorityPresentation` types `membership` as a `String`
        // and `authority` as `Vec<String>`; handed objects a host refuses the whole request
        // as "invalid type: map, expected a string", which reads as a malformed payload
        // rather than as a shape mismatch. Leaf first, then the credential the room issued,
        // so every link the host relies on is present — it will not fetch one.
        Ok(serde_json::json!({
            "membership": serde_json::to_string(membership).map_err(|e| e.to_string())?,
            "authority": [
                serde_json::to_string(leaf.credential()).map_err(|e| e.to_string())?,
                serde_json::to_string(authority).map_err(|e| e.to_string())?,
            ],
        }))
    }

    /// Attach this key's `eddsa-jcs-2022` proof to a request.
    ///
    /// What proves the *room* identity authored it, as distinct from what DIDComm proves
    /// about the transport identity that carried it.
    async fn sign(&self, request: &wire::AdmissionRequest) -> Result<serde_json::Value, String> {
        let doc =
            serde_json::to_value(request).map_err(|e| format!("serialise the request: {e}"))?;
        self.sign_document(&doc).await
    }

    /// Attach the proof to any JSON document.
    ///
    /// One signer for both conversations, because they are the same act: an admission
    /// request and a Trust Task are both documents this key authors, and a counterparty
    /// takes the author from the proof either way. A second signer would be a second place
    /// for the proof to be built slightly differently.
    async fn sign_document(
        &self,
        document: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let mut doc = document.clone();
        // A proof never covers itself.
        doc.as_object_mut()
            .ok_or("a signable document must be a JSON object")?
            .remove("proof");

        let proof = affinidi_data_integrity::DataIntegrityProof::sign(
            &doc,
            &self.secret,
            affinidi_data_integrity::SignOptions::new(),
        )
        .await
        .map_err(|e| format!("sign the document: {e}"))?;
        doc.as_object_mut()
            .ok_or("a signable document must be a JSON object")?
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

/// What a member holds after being admitted, and needs for every request afterwards.
///
/// Grouped because these five travel together and never separately: the host to ask, the room
/// to ask about, the key that signs, and the two credentials the room issued. Passing them
/// one at a time made a seven-argument call in which two `&str` sat adjacent and either order
/// compiled.
struct Membership<'a> {
    host: &'a str,
    room_did: &'a str,
    member: &'a MemberKey,
    admitted: &'a wire::Admitted,
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

    /// Send one signed Trust Task to a **host** and return its response payload.
    ///
    /// The other party this member talks to, and a different kind of conversation from
    /// admission: a room's owner is asked to *decide* something, a host is asked to *act*.
    /// So this is a Trust Task, which already has a binding for each carrier — DIDComm wraps
    /// the document under one reserved envelope type, TSP sends it with no wrapper at all,
    /// byte-identical to what a POST would carry.
    ///
    /// Nothing about who is asking comes from the carrier. The host takes the presenter from
    /// the document's own proof and the authority from the chain inside it, so this is one
    /// signature that could have gone either way.
    async fn host_task(
        &self,
        room: &Membership<'_>,
        type_uri: &str,
        action: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let (host, room_did, member) = (room.host, room.room_did, room.member);
        let presentation = member
            .present(&room.admitted.authority, &room.admitted.membership, action)
            .await?;

        let mut body = serde_json::json!({
            "roomId": room_did,
            "presentation": presentation,
        });
        for (k, v) in payload.as_object().into_iter().flatten() {
            body[k] = v.clone();
        }

        let document = serde_json::json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": body,
        });
        let signed = member.sign_document(&document).await?;

        let id = signed["id"].as_str().unwrap_or_default().to_string();
        let answer = if self.over_tsp {
            self.send_tsp_document(host, &id, &signed).await?;
            self.await_reply(host, &id).await?.1
        } else {
            self.send_didcomm(host, &id, TRUST_TASK_ENVELOPE, signed)
                .await?;
            self.await_reply(host, &id).await?.1
        };

        // The answer is the document and it says for itself whether it is one — no status
        // came with it and none is missed.
        if answer["type"]
            .as_str()
            .is_some_and(|t| t.contains("trust-task-error"))
        {
            let p = &answer["payload"];
            return Err(format!(
                "the host refused: {}",
                p["reason"]
                    .as_str()
                    .or(p["code"].as_str())
                    .unwrap_or("(no reason)")
            ));
        }
        Ok(answer["payload"].clone())
    }

    /// A Trust-Task document over TSP: the payload **is** the document, no wrapper.
    async fn send_tsp_document(
        &self,
        to: &str,
        _id: &str,
        document: &serde_json::Value,
    ) -> Result<(), String> {
        let bytes = serde_json::to_vec(document).map_err(|e| e.to_string())?;
        self.atm
            .tsp()
            .send_routed(
                &self.profile,
                &[self.mediator_did.clone(), to.to_string()],
                &bytes,
            )
            .await
            .map_err(|e| format!("send the TSP request: {e}"))
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

            let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(&frame.message.payload)
            else {
                continue;
            };

            // DIDComm threads in the envelope's own `thid`; TSP has no header to thread it,
            // so the reply carries one. Accept either, and never "the next frame" — the
            // mediator's own status messages arrive on this socket too.
            let threaded = frame
                .thread_id
                .clone()
                .or_else(|| string_at(&envelope, "threadId"))
                .or_else(|| string_at(&envelope, "thid"))
                .or_else(|| {
                    envelope
                        .get("document")
                        .and_then(|d| string_at(d, "threadId"))
                })
                .unwrap_or_default();
            if threaded != id {
                continue;
            }

            // Two kinds of correspondent answer here. A room's owner replies in the demo's
            // own protocol — `{ type, body }`, which is not a Trust Task and has no thread of
            // its own, so it carries `thid`. A host replies with a **bare Trust-Task
            // document**, which threads itself with `threadId`.
            //
            // A wrapped `{ thid, document }` is still accepted, because a host may predate
            // OpenVTC/verifiable-trust-infrastructure#1383 — but it is no longer what either
            // host sends, and expecting it was why this client could read `room-host` and not
            // a VTC.
            let document = envelope.get("document").unwrap_or(&envelope);
            if document.get("threadId").is_some() {
                return Ok((
                    document
                        .get("type")
                        .and_then(|t| t.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    document.clone(),
                ));
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
                let code = body
                    .get("code")
                    .and_then(|c| c.as_str())
                    .unwrap_or("(no code)");
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

/// One string member, if it is there and is a string.
fn string_at(value: &serde_json::Value, member: &str) -> Option<String> {
    value.get(member)?.as_str().map(str::to_string)
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
