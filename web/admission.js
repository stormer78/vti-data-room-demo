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
  packAuthcryptJson,
  resolveKeyAgreement,
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

/// The mediator a room advertises, or `null` if it advertises none.
///
/// **The lookup that makes a room addressable.** `did:peer` resolution is pure computation,
/// so this costs no network and works offline — the property that let a room be a
/// `did:peer` rather than something that needs a registry.
///
/// `serviceEndpoint.uri` is the mediator's **DID**, not a URL, matching how the `ai-agent`
/// and `room` `did:webvh` templates advertise `DIDCommMessaging`. A client dials the
/// mediator by DID, which is what lets every room on one mediator share one connection.
export function advertisedMediator(roomDid) {
  if (!roomDid.startsWith("did:peer:")) return null;
  const { didDocument } = didPeer.resolve(roomDid);
  for (const service of didDocument.service ?? []) {
    const types = Array.isArray(service.type) ? service.type : [service.type];
    if (!types.includes("DIDCommMessaging") && !types.includes("dm")) continue;
    const uri = endpointUri(service.serviceEndpoint);
    if (uri) return uri;
  }
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

/// One connection to a mediator, and the request/reply plumbing over it.
///
/// The reply is matched by DIDComm `thid`, not by "the next frame that arrives": a mediator
/// delivers status messages and pings of its own, and a client that took the first thing off
/// the socket would read one of those as the owner's answer.
export class OwnerConnection {
  constructor(connection, holder, roomDid, mediatorDid, roomKeyAgreement, mediatorKeyAgreement) {
    this.connection = connection;
    this.holder = holder;
    this.roomDid = roomDid;
    this.mediatorDid = mediatorDid;
    this.room = roomKeyAgreement;
    this.mediator = mediatorKeyAgreement;
  }

  /// Open a connection to the owner of `roomDid`, through the mediator that room advertises.
  static async open(roomDid, holder) {
    const mediatorDid = advertisedMediator(roomDid);
    if (!mediatorDid) {
      throw new Error(
        `${roomDid} advertises no DIDComm service, so there is nowhere to ask to join — a `
          + `did:key room can be verified but not reached`,
      );
    }
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
    );
  }

  /// Send one message to the room and wait for the reply threaded to it.
  ///
  /// Two hops, because a mediator refuses direct delivery of inner messages: authcrypt to
  /// the room, then wrap that in a `routing/2.0/forward` addressed to the mediator, which
  /// unwraps it and queues the inner envelope for the room's pickup.
  async ask(type, body) {
    const id = crypto.randomUUID();
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
    const message_ = await reply;

    if (String(message_.type ?? "").includes("problem-report")) {
      const b = message_.body ?? {};
      throw new Error(`the owner refused [${b.code ?? "no code"}]: ${b.comment ?? ""}`);
    }
    return message_;
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
