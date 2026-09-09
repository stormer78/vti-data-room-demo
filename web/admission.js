// Joining a room over **DIDComm**, knowing nothing but its DID.
//
// This is the half of "one site, any number of rooms" that the HTTP path could not carry.
// Working *in* a room only ever needed the host, so that worked against any host from a
// link. Being let *in* needs the room's owner — and the only way to reach an owner was the
// sample's own catalogue, so the site could admit you only to a room it was configured for.
//
// A `did:peer:2` room carries a service block saying which mediator its owner listens on.
// Resolving it is arithmetic on the identifier: no network, no registry, no configuration.
// Everything below follows from that one lookup.
//
// # A member holds two identities and they are not interchangeable
//
// - the **room identity** (`did:key`, in wasm) — what the room's credentials name, and what
//   signs every document a host later authenticates. Its secret never enters this file.
// - the **transport identity** (`did:peer:2`, here) — how the mediator addresses us, and
//   what DIDComm's authcrypt proves. Disposable: minted per session, worth nothing on its
//   own.
//
// The split is forced rather than chosen. DIDComm's authcrypt needs an X25519 secret in the
// caller's hands, which means in this file; the room identity exists precisely so that its
// secret is *not*. One key could not do both without giving up one of the two properties.
//
// So a request carries **two** proofs and the owner checks they agree: the DIDComm envelope
// proves the transport DID sent it, an `eddsa-jcs-2022` proof inside the body proves the
// room DID authored it, and the body names the transport DID so the two are bound. Without
// that last part a signed request is a bearer artefact — anybody who saw one could send it
// from their own connection and be handed the invitation.

import {
  buildHolder,
  connectMediatorSession,
  createDidPeer2,
  didPeer,
  ed25519,
  x25519,
  multibase,
  packAuthcryptJson,
  resolveKeyAgreement,
  tspPack,
  tspPackRouted,
  tspUnpack,
  wrapForward,
} from "./vendor/didcomm.js";

/// The protocol, and the reason it is not a Trust Task.
///
/// `rooms/owner/{invite,issue-membership,issue-authority}` are real Trust Tasks and the
/// owner performs all three — but a Trust Task is an instruction you give **your own**
/// agent, authorised by your control of it. A stranger asking an owner to *decide* something
/// is the opposite, and calling it a Trust Task would say the stranger may instruct the
/// room's agent.
export const REQUEST_INVITATION = "https://dataroom.demo/admission/0.1/request-invitation";
export const INVITATION = "https://dataroom.demo/admission/0.1/invitation";
export const REQUEST_ADMISSION = "https://dataroom.demo/admission/0.1/request-admission";
export const ADMITTED = "https://dataroom.demo/admission/0.1/admitted";

const REPLY_TIMEOUT_MS = 30_000;

/// What a room advertises: where its owner listens, and over what.
///
/// **The lookup that makes a room addressable.** `did:peer` resolution is pure computation,
/// so this costs no network and works offline — the property that let a room be a
/// `did:peer` rather than something that needs a registry.
///
/// `serviceEndpoint.uri` is the mediator's **DID**, not a URL, matching how the `ai-agent`
/// and `room` `did:webvh` templates advertise `DIDCommMessaging`. A client dials the
/// mediator by DID, which is what lets every room on one mediator share one connection.
///
/// Returns `null` when the room advertises nothing — a `did:key` room, which can be
/// verified but not reached.
export function advertisedMediator(roomDid) {
  if (!roomDid.startsWith("did:peer:")) return null;
  const { didDocument } = didPeer.resolve(roomDid);

  let found = null;
  for (const service of didDocument.service ?? []) {
    const types = Array.isArray(service.type) ? service.type : [service.type];
    // `dm` is the did:peer abbreviation for `DIDCommMessaging`; a resolver may expand it or
    // leave it, so both spellings mean the same service.
    const didcomm = types.includes("DIDCommMessaging") || types.includes("dm");
    const tsp = types.includes("TSPTransport");
    if (!didcomm && !tsp) continue;

    const uri = endpointUri(service.serviceEndpoint);
    if (!uri) continue;

    // One mediator per room. A second service naming a different one would mean two places
    // to ask and nothing saying which answers, so the first wins and the rest are read only
    // for the carriers they add.
    if (!found) found = { mediator: uri, tsp, didcomm };
    else if (found.mediator === uri) {
      found.tsp ||= tsp;
      found.didcomm ||= didcomm;
    }
  }
  return found;
}

/// The carrier to use: **TSP if the room offers it, DIDComm otherwise.**
///
/// Chosen from what the room says rather than from what happens to work. A mediator carries
/// both on one socket, so a client that always spoke TSP would usually succeed — and would
/// break, with nothing in the room's document having changed, the first time it met an owner
/// that served only DIDComm.
export function preferredCarrier(advertised) {
  if (!advertised) return null;
  if (advertised.tsp) return "tsp";
  if (advertised.didcomm) return "didcomm";
  return null;
}

/// A service endpoint is allowed several shapes; take the URI out of whichever this is.
function endpointUri(endpoint) {
  if (typeof endpoint === "string") return endpoint;
  if (Array.isArray(endpoint)) {
    for (const e of endpoint) {
      const uri = endpointUri(e);
      if (uri) return uri;
    }
    return null;
  }
  if (endpoint && typeof endpoint === "object") return endpointUri(endpoint.uri);
  return null;
}

/// Mint a transport identity — Ed25519 root, X25519 derived, wrapped as a `did:peer:2`.
///
/// Fresh every session, and that is not laziness. It is a routing address and nothing else:
/// nothing is issued to it, nothing it signs outlives the connection, and losing it costs a
/// reconnect. Persisting it would give a member a second long-lived identifier when the
/// whole point is that they have exactly one.
///
/// The X25519 half is the Montgomery form of the same Ed25519 secret — the derivation the
/// wallet's own holder identity uses. That matters rather than being a detail: it is what
/// makes the key the mediator authenticates us by the same key our DID advertises, so a
/// counterparty resolving us reaches the key we actually hold.
export function mintTransportIdentity() {
  const edSecret = crypto.getRandomValues(new Uint8Array(32));
  const edPublic = ed25519.getPublicKey(edSecret);
  const xPrivate = ed25519.utils.toMontgomerySecret(edSecret);
  const xPublic = x25519.getPublicKey(xPrivate);

  const peer = createDidPeer2({
    ed25519PublicKey: edPublic,
    x25519PublicKey: xPublic,
  });
  // `buildHolder` re-derives the same X25519 pair from the same secret; the DID above
  // advertises it. The two agreeing is the whole contract, so they are derived side by side
  // rather than in two places that could drift.
  return buildHolder(edSecret, peer.did, peer.authKid, peer.keyAgreementKid);
}

/// The Ed25519 verification key a `did:peer` names, from its own identifier.
///
/// TSP verifies the outer signature against this, where DIDComm verifies the envelope
/// against the key-agreement key — two different keys doing the same job for two carriers,
/// and both recoverable from the DID without a network.
function verificationKey(did) {
  const { didDocument } = didPeer.resolve(did);
  for (const vm of didDocument.verificationMethod ?? []) {
    if (!vm.publicKeyMultibase) continue;
    const { codec, key } = multibase.decodeMultikey(vm.publicKeyMultibase);
    // `0xed 0x01` — Ed25519. The key-agreement half is `0xec 0x01`, and signing with it is
    // not possible, so this picks by what the key *is* rather than by its position.
    if (codec[0] === 0xed && codec[1] === 0x01) return key;
  }
  throw new Error(`${did} names no Ed25519 verification key, so nothing it sends can be verified`);
}

/// One connection to a mediator, and the request/reply plumbing over it — on either carrier.
///
/// **One socket for both.** A mediator permits one websocket per DID and sniffs the TSP
/// magic byte on a binary frame to decide which handler gets it, so TSP rides the DIDComm
/// session rather than opening a second connection. A second socket is not an alternative:
/// the mediator evicts one of them as a duplicate channel.
///
/// The reply is matched by thread, not by "the next frame that arrives": a mediator delivers
/// status messages and pings of its own, and a client that took the first thing off the
/// socket would read one of those as the owner's answer. DIDComm threads in its envelope;
/// TSP has no headers at all, so the reply carries its own `thid`.
export class OwnerConnection {
  constructor(connection, holder, roomDid, mediatorDid, roomKeyAgreement, mediatorKeyAgreement, carrier) {
    this.connection = connection;
    this.holder = holder;
    this.roomDid = roomDid;
    this.mediatorDid = mediatorDid;
    this.room = roomKeyAgreement;
    this.mediator = mediatorKeyAgreement;
    this.carrier = carrier;
  }

  /// Open a connection to the owner of `roomDid`, through the mediator that room advertises.
  static async open(roomDid, holder, carrier) {
    const advertised = advertisedMediator(roomDid);
    if (!advertised) {
      throw new Error(
        `${roomDid} advertises no service, so there is nowhere to ask to join — a `
          + `did:key room can be verified but not reached`,
      );
    }
    const mediatorDid = advertised.mediator;
    carrier ??= preferredCarrier(advertised);
    const connection = await connectMediatorSession({
      holder: holder.identity,
      mediatorDid,
      // Named `vtaDid` by the library because a wallet's counterparty is usually a VTA.
      // Here it is the room: the parameter is "whose keys should inbound replies unpack
      // against", and the room is the party that answers.
      vtaDid: roomDid,
    });
    return new OwnerConnection(
      connection,
      holder,
      roomDid,
      mediatorDid,
      connection.vta,
      connection.mediator,
      carrier,
    );
  }

  /// The TSP keys for this member and the two parties it seals to.
  ///
  /// The member's X25519 half is the Montgomery form of its Ed25519 secret — the same
  /// derivation the `did:peer:2` above advertises, which is what makes the key a
  /// counterparty resolves the key we actually hold.
  tspKeys() {
    const edSecret = this.holder.signing.privateKey;
    const senderEncryptionKey = ed25519.utils.toMontgomerySecret(edSecret);
    return {
      senderSigningKey: edSecret,
      senderEncryptionKey,
      room: rawX25519(this.room.keyAgreementPublicJwk),
      mediator: rawX25519(this.mediator.keyAgreementPublicJwk),
    };
  }

  /// Send one message to the room and wait for the reply threaded to it.
  ///
  /// Two hops, because a mediator refuses direct delivery of inner messages: authcrypt to
  /// the room, then wrap that in a `routing/2.0/forward` addressed to the mediator, which
  /// unwraps it and queues the inner envelope for the room's pickup.
  async ask(type, body) {
    const id = crypto.randomUUID();
    return this.carrier === "tsp"
      ? await this.askOverTsp(id, type, body)
      : await this.askOverDidcomm(id, type, body);
  }

  /// TSP: seal end-to-end to the room, wrap in a routing layer sealed to the mediator, and
  /// send as a binary frame on the shared socket.
  ///
  /// The envelope is `{ id, type, body }` *in the payload*, because TSP has no headers.
  /// DIDComm supplies `type` and `thid` around the message; over TSP the message carries
  /// them itself. The same three fields either way, which is what lets one owner-side
  /// decision serve both.
  async askOverTsp(id, type, body) {
    const keys = this.tspKeys();
    const vid = this.holder.identity.did;
    const payload = new TextEncoder().encode(JSON.stringify({ id, type, body }));

    const inner = await tspPack(payload, vid, this.roomDid, {
      senderSigningKey: keys.senderSigningKey,
      senderEncryptionKey: keys.senderEncryptionKey,
      receiverEncryptionKey: keys.room,
    });
    const routed = await tspPackRouted(inner.bytes, [this.roomDid], vid, this.mediatorDid, {
      senderSigningKey: keys.senderSigningKey,
      senderEncryptionKey: keys.senderEncryptionKey,
      receiverEncryptionKey: keys.mediator,
    });

    // The predicate decides which inbound frame *is* this reply. Without one the next frame
    // to arrive would be handed to this waiter — and the mediator sends frames of its own.
    // Only this layer can tell them apart, because only it holds the keys, so the predicate
    // unpacks and keeps what it decoded rather than making the caller unpack again.
    const roomSigning = verificationKey(this.roomDid);
    let decoded = null;
    const claims = async (bytes) => {
      try {
        const message = await tspUnpack(bytes, {
          receiverDecryptionKey: keys.senderEncryptionKey,
          senderEncryptionKey: keys.room,
          senderSigningKey: roomSigning,
        });
        const envelope = JSON.parse(new TextDecoder().decode(message.payload));
        if (envelope.thid !== id) return false;
        decoded = envelope;
        return true;
      } catch {
        return false;
      }
    };

    // Register the waiter before sending — both synchronous, so no frame can arrive between
    // them and be handed to nobody.
    const reply = this.connection.awaitTspFrame(REPLY_TIMEOUT_MS, claims);
    this.connection.sendBinary(routed.bytes);
    await reply;

    return this.checked(decoded);
  }

  /// DIDComm: two hops, because a mediator refuses direct delivery of inner messages —
  /// authcrypt to the room, then wrap that in a `routing/2.0/forward` addressed to the
  /// mediator, which unwraps it and queues the inner envelope for the room's pickup.
  async askOverDidcomm(id, type, body) {
    const message = JSON.stringify({
      id,
      type,
      from: this.holder.identity.did,
      to: [this.roomDid],
      created_time: Math.floor(Date.now() / 1000),
      body,
    });

    const inner = await packAuthcryptJson(message, this.holder.identity, [
      { kid: this.room.keyAgreementKid, jwk: this.room.keyAgreementPublicJwk },
    ]);
    const forward = wrapForward(this.roomDid, this.holder.identity.did, this.mediatorDid, inner);
    const outer = await packAuthcryptJson(forward, this.holder.identity, [
      { kid: this.mediator.keyAgreementKid, jwk: this.mediator.keyAgreementPublicJwk },
    ]);

    // Register the waiter before sending, so a fast reply cannot arrive before anything is
    // listening for it.
    const reply = this.connection.waitFor(id, REPLY_TIMEOUT_MS);
    this.connection.send(outer);
    return this.checked(await reply);
  }

  /// A refusal is an answer, not a transport failure — surface what the owner said.
  checked(message) {
    if (!message) throw new Error("the owner sent nothing this request could use");
    if (String(message.type ?? "").includes("problem-report")) {
      const b = message.body ?? {};
      throw new Error(`the owner refused [${b.code ?? "no code"}]: ${b.comment ?? ""}`);
    }
    return message;
  }

  close() {
    try {
      this.connection.close();
    } catch {}
  }
}

/// Build the body of a request and have the **room** identity sign it.
///
/// Signed in wasm, so the key that will later sign records is the key that asks — and its
/// secret never reaches this file.
export function signedRequest(identity, roomDid, transportDid, extra = {}) {
  const body = {
    roomDid,
    memberDid: identity.did,
    transportDid,
    ...extra,
  };
  return JSON.parse(identity.signDocument(JSON.stringify(body)));
}

/// The raw 32 bytes behind an X25519 public JWK.
function rawX25519(jwk) {
  const b64 = jwk.x.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
