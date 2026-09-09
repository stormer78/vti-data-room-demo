// Reaching another party through a mediator — the transport, and nothing above it.
//
// Two different conversations run over this and neither belongs to it: **admission**, which
// asks a room's owner to let you in, and **records**, which asks a room's host to store and
// serve what you write. They are different parties, different protocols, and — importantly —
// a member is not obliged to reach them the same way.
//
// # One socket per mediator, not per correspondent
//
// A mediator permits **one websocket per DID** and multiplexes TSP and DIDComm onto it,
// sniffing the TSP magic byte on a binary frame. So a member holds one socket per mediator
// and addresses everybody through it. Opening a second for a second correspondent is not an
// alternative: the mediator evicts one of the pair as a duplicate channel, and the symptom is
// a connection that works until the moment something else connects.
//
// A room's owner and its host are usually on the same mediator, so usually that is one socket
// for everything. When they are not, this holds one per mediator — which is the actual
// constraint, rather than one per party.
//
// # The member's two identities
//
// - the **transport identity** (`did:peer:2`, minted here) — how a mediator addresses us, and
//   what authcrypt and TSP prove about the sender. Disposable: nothing is issued to it and
//   nothing it signs outlives the connection.
// - the **room identity** (`did:key`, in wasm) — what credentials name and what signs every
//   document a room or a host authenticates. Its secret never enters this file.
//
// The split is forced rather than chosen. Authcrypt and TSP both need an X25519 secret in the
// caller's hands, which means in this file; the room identity exists precisely so that its
// secret is not. One key could not do both without giving up one of the two properties.

import {
  buildHolder,
  connectMediatorSession,
  createDidPeer2,
  didPeer,
  resolveDidDocument,
  ed25519,
  x25519,
  multibase,
  packAuthcryptJson,
  tspPack,
  tspPackRouted,
  tspUnpack,
  wrapForward,
} from "./vendor/didcomm.js";

/// The DIDComm `type` a Trust-Task envelope rides under, per the framework binding
/// `https://trusttasks.org/binding/didcomm/0.1`: one reserved type whose `body` carries the
/// whole document. A conformant peer rejects anything else, and — worth knowing — rejects it
/// *silently*, because "not an envelope" and "not addressed to me" look identical from
/// outside.
export const TRUST_TASK_ENVELOPE = "https://trusttasks.org/binding/didcomm/0.1/envelope";

const REPLY_TIMEOUT_MS = 30_000;

/// What a DID advertises: where it listens, and over what.
///
/// **The lookup that makes a party addressable.** `did:peer` resolution is pure computation,
/// so this costs no network and works offline — the property that lets a room and a host be
/// `did:peer`s rather than things that need a registry.
///
/// `serviceEndpoint.uri` is the mediator's **DID**, not a URL, matching how the `ai-agent`
/// and `room` `did:webvh` templates advertise `DIDCommMessaging`. A client dials the mediator
/// by DID, which is what lets everybody on one mediator share one socket.
///
/// `null` when the DID advertises nothing — a `did:key`, which can be verified but not
/// reached.
export async function advertised(did) {
  // Any method the stack resolves, not only `did:peer`. That mattered the moment this site
  // was pointed at anything real: a production room is a `did:webvh`, and so is a
  // VTC-hosted one, so a `did:peer`-only lookup could reach the sample's rooms and nothing
  // else. `did:key` and `did:peer` still cost no network — the resolver computes them — and
  // `did:webvh` fetches and verifies its log, which is why this is async.
  const didDocument = await resolveDidDocument(did).catch(() => null);
  if (!didDocument) return null;

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

    // One mediator per party. A second service naming a different one would mean two places
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

/// The carrier to use: **TSP if it is offered, DIDComm otherwise.**
///
/// Chosen from what the counterparty says rather than from what happens to work. A mediator
/// carries both on one socket, so a client that always spoke TSP would usually succeed — and
/// would break, with nothing in the other party's document having changed, the first time it
/// met one that served only DIDComm.
export function preferredCarrier(a) {
  if (!a) return null;
  if (a.tsp) return "tsp";
  if (a.didcomm) return "didcomm";
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
/// reconnect. Persisting it would give a member a second long-lived identifier when the whole
/// point is that they have exactly one.
///
/// The X25519 half is the Montgomery form of the same Ed25519 secret — the derivation the
/// wallet's own holder identity uses. That matters rather than being a detail: it makes the
/// key a mediator authenticates us by the same key our DID advertises, so a counterparty who
/// resolves us reaches the key we actually hold.
export function mintTransportIdentity() {
  const edSecret = crypto.getRandomValues(new Uint8Array(32));
  const edPublic = ed25519.getPublicKey(edSecret);
  const xPrivate = ed25519.utils.toMontgomerySecret(edSecret);
  const xPublic = x25519.getPublicKey(xPrivate);

  const peer = createDidPeer2({ ed25519PublicKey: edPublic, x25519PublicKey: xPublic });
  // `buildHolder` re-derives the same X25519 pair from the same secret, and the DID above
  // advertises it. The two agreeing is the whole contract, so they are derived side by side
  // rather than in two places that could drift.
  return buildHolder(edSecret, peer.did, peer.authKid, peer.keyAgreementKid);
}

/// The Ed25519 verification key a `did:peer` names, from its own identifier.
///
/// TSP verifies the outer signature against this; DIDComm verifies its envelope against the
/// key-agreement key. Two keys doing the same job for two carriers, both recoverable from the
/// DID without a network.
async function verificationKey(did) {
  const didDocument = await resolveDidDocument(did);
  for (const vm of didDocument.verificationMethod ?? []) {
    if (!vm.publicKeyMultibase) continue;
    const { codec, key } = multibase.decodeMultikey(vm.publicKeyMultibase);
    // `0xed 0x01` — Ed25519. The key-agreement half is `0xec 0x01` and cannot sign, so this
    // picks by what the key *is* rather than by where it sits.
    if (codec[0] === 0xed && codec[1] === 0x01) return key;
  }
  throw new Error(`${did} names no Ed25519 verification key, so nothing it sends can be verified`);
}

/// The raw 32 bytes behind an X25519 public JWK.
function rawX25519(jwk) {
  const b64 = jwk.x.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/// One socket to one mediator, addressing anybody reachable through it.
export class MediatorLink {
  #connection;
  #holder;
  #mediatorDid;
  #mediatorKeys;
  #peers = new Map();

  constructor(connection, holder, mediatorDid) {
    this.#connection = connection;
    this.#holder = holder;
    this.#mediatorDid = mediatorDid;
    this.#mediatorKeys = connection.mediator;
  }

  get transportDid() {
    return this.#holder.identity.did;
  }

  /// Whether the socket underneath is still live.
  ///
  /// Checked before a cached link is handed back. Without it a dropped socket is invisible
  /// until the next request times out, and every request after that times out too — the page
  /// looks hung rather than disconnected, and reconnecting is the one thing it will not try.
  get isOpen() {
    return this.#connection.isOpen;
  }

  /// Open a link to `mediatorDid`, seeded with `firstPeer`'s keys.
  ///
  /// The session resolves any *other* correspondent's keys on demand, so one seed is enough —
  /// which is what makes this a link to a mediator rather than to a party.
  ///
  /// `onDropped` fires when the socket goes away on its own, as against being closed here.
  /// The caller uses it to forget this link, so the next request opens a fresh one instead of
  /// waiting on a socket nobody is listening to.
  static async open(mediatorDid, holder, firstPeer, onDropped) {
    const connection = await connectMediatorSession({
      holder: holder.identity,
      mediatorDid,
      // Named `vtaDid` by the library because a wallet's counterparty is usually a VTA. The
      // parameter is "whose keys should inbound replies unpack against"; here that is
      // whichever party we are about to talk to.
      vtaDid: firstPeer,
      ...(onDropped ? { onClose: onDropped } : {}),
    });
    const link = new MediatorLink(connection, holder, mediatorDid);
    link.#peers.set(firstPeer, connection.vta);
    return link;
  }

  /// This correspondent's key-agreement material, resolved once and kept.
  async #peer(did) {
    if (!this.#peers.has(did)) {
      const { resolveKeyAgreement } = await import("./vendor/didcomm.js");
      this.#peers.set(did, await resolveKeyAgreement(did));
    }
    return this.#peers.get(did);
  }

  /// Ask `to` a question in a **plain DIDComm protocol** — a message with its own `type`.
  ///
  /// What admission uses. Over TSP, which has no headers at all, the same three fields ride
  /// *in* the payload as `{ id, type, body }`; over DIDComm they ride around it. Same three
  /// fields either way, which is what lets one responder serve both.
  async askProtocol(to, carrier, type, body) {
    const id = crypto.randomUUID();
    // `checked` on both arms, not just DIDComm's. It was on one, and the effect was that the
    // same refusal read as the counterparty's own words over one carrier and as "expected
    // commits, got problem-report" over the other — the reason discarded by the layer that
    // had it in its hand. A rule that holds on one wire and not the other is the thing this
    // whole class is arranged to prevent.
    const reply =
      carrier === "tsp"
        ? checked(await this.#tsp(to, id, { id, type, body }, (e) => threadOf(e) === id))
        : await this.#didcomm(to, id, type, body);
    return { type: reply.type, body: reply.body };
  }

  /// Ask `to` a **Trust Task**, and get its response document back.
  ///
  /// What records use, and the difference from `askProtocol` is worth stating: this is not a
  /// protocol invented here. A Trust Task is already an instruction to a service, with a
  /// binding for every carrier — the DIDComm one wraps the document under a single reserved
  /// envelope `type`, and the TSP one is the document itself, byte-identical to the HTTP body
  /// with no wrapper at all.
  ///
  /// The answer is the document. It is self-describing — its own `type`, and a framework
  /// `code` when it refuses — so a caller switches on what is in it and never on how it
  /// arrived. That is why the HTTP status has no counterpart here and is not missed.
  async askTrustTask(to, carrier, document) {
    const id = document.id ?? crypto.randomUUID();
    if (carrier === "tsp") {
      // **Neither direction is wrapped.** A request's type is the document's own `type`
      // field, and a response threads itself: it carries `threadId`, set to the request's
      // `id`. Nothing needs adding around either.
      //
      // This used to expect `{ thid, document }` — what `room-host` sent and `vtc-service`
      // never did — so one client could read one host and not the other, and the failure was
      // a reply no waiter matched, which looks exactly like a timeout. See
      // OpenVTC/verifiable-trust-infrastructure#1383. A wrapper is still *accepted*, because
      // that is cheap and a host may be older than the fix; it is neither sent nor required.
      //
      // `checked` because a counterparty that never got as far as dispatching answers with a
      // problem-report, and that must surface rather than arriving as an undefined document.
      const answer = checked(await this.#tsp(to, id, document, (e) => threadOf(e) === id));
      return answer.document ?? answer;
    }
    const reply = await this.#didcomm(to, id, TRUST_TASK_ENVELOPE, document);
    return reply.body;
  }

  /// DIDComm: authcrypt to the recipient, then wrap in a `routing/2.0/forward` addressed to
  /// the mediator — two hops, because a mediator refuses direct delivery of inner messages.
  /// It unwraps the outer envelope, sees the next hop, and queues the inner one, having held
  /// the plaintext of neither.
  async #didcomm(to, id, type, body) {
    const peer = await this.#peer(to);
    const message = JSON.stringify({
      id,
      type,
      from: this.transportDid,
      to: [to],
      created_time: Math.floor(Date.now() / 1000),
      body,
    });

    const inner = await packAuthcryptJson(message, this.#holder.identity, [
      { kid: peer.keyAgreementKid, jwk: peer.keyAgreementPublicJwk },
    ]);
    const forward = wrapForward(to, this.transportDid, this.#mediatorDid, inner);
    const outer = await packAuthcryptJson(forward, this.#holder.identity, [
      { kid: this.#mediatorKeys.keyAgreementKid, jwk: this.#mediatorKeys.keyAgreementPublicJwk },
    ]);

    // Register the waiter before sending, so a fast reply cannot arrive before anything is
    // listening for it.
    const reply = this.#connection.waitFor(id, REPLY_TIMEOUT_MS);
    this.#connection.send(outer);
    return checked(await reply);
  }

  /// TSP: seal end-to-end to the recipient, wrap in a routing layer sealed to the mediator,
  /// and send as a binary frame on the shared socket.
  async #tsp(to, id, payload, matches) {
    const peer = await this.#peer(to);
    const edSecret = this.#holder.signing.privateKey;
    const senderEncryptionKey = ed25519.utils.toMontgomerySecret(edSecret);
    const keys = { senderSigningKey: edSecret, senderEncryptionKey };
    const peerKey = rawX25519(peer.keyAgreementPublicJwk);

    const bytes = new TextEncoder().encode(JSON.stringify(payload));
    const inner = await tspPack(bytes, this.transportDid, to, {
      ...keys,
      receiverEncryptionKey: peerKey,
    });
    const routed = await tspPackRouted(inner.bytes, [to], this.transportDid, this.#mediatorDid, {
      ...keys,
      receiverEncryptionKey: rawX25519(this.#mediatorKeys.keyAgreementPublicJwk),
    });

    // The predicate decides which inbound frame *is* this reply. Without one the next frame
    // to arrive would be handed to this waiter, and a mediator sends frames of its own. Only
    // this layer can tell them apart because only it holds the keys, so the predicate unpacks
    // and keeps what it decoded rather than making the caller unpack again.
    const peerSigning = await verificationKey(to);
    let decoded = null;
    const claims = async (frame) => {
      try {
        const message = await tspUnpack(frame, {
          receiverDecryptionKey: senderEncryptionKey,
          senderEncryptionKey: peerKey,
          senderSigningKey: peerSigning,
        });
        const envelope = JSON.parse(new TextDecoder().decode(message.payload));
        if (!matches(envelope)) return false;
        decoded = envelope;
        return true;
      } catch {
        return false;
      }
    };

    // Register the waiter before sending — both synchronous, so no frame can arrive between
    // them and be handed to nobody.
    const reply = this.#connection.awaitTspFrame(REPLY_TIMEOUT_MS, claims);
    this.#connection.sendBinary(routed.bytes);
    await reply;
    if (!decoded) throw new Error("the reply arrived but could not be read");
    return decoded;
  }

  close() {
    try {
      this.#connection.close();
    } catch {}
  }
}

/// What a TSP frame threads on, whichever shape it arrived in.
///
/// A Trust-Task document threads itself with `threadId`. The demo's own admission protocol,
/// which is not a Trust Task and has no such field, carries `thid`. A wrapped reply from an
/// older host carries `thid` outside the document. All three mean the same thing.
function threadOf(envelope) {
  return envelope.threadId ?? envelope.thid ?? envelope.document?.threadId;
}

/// A refusal is an answer, not a transport failure — surface what was said.
function checked(message) {
  if (!message) throw new Error("nothing came back that this request could use");
  if (String(message.type ?? "").includes("problem-report")) {
    const b = message.body ?? {};
    throw new Error(`refused [${b.code ?? "no code"}]: ${b.comment ?? ""}`);
  }
  return message;
}

/// One link per mediator, for the life of the page.
///
/// Keyed by mediator rather than by correspondent, because that is the actual constraint: a
/// mediator allows this DID one socket, and a second would evict the first. Two parties on one
/// mediator therefore share a link; two mediators get one each.
const links = new Map();

/// The link to reach `peerDid` over, opening one if this page has none to its mediator.
///
/// Returns `null` when the party advertises nowhere — a `did:key`, which can be verified but
/// not reached.
export async function linkTo(peerDid, holder) {
  const a = await advertised(peerDid);
  if (!a) return null;

  // A cached link is only worth reusing while its socket is up. A dropped one answers nothing
  // and cannot say so, so every request on it waits out its timeout — the page looks hung
  // rather than disconnected. Two checks rather than one: `onClose` catches a drop the moment
  // it happens, and `isOpen` catches the case where it happened before this page was looking.
  const cached = links.get(a.mediator);
  if (cached && !cached.isOpen) {
    links.delete(a.mediator);
    cached.close();
  }

  if (!links.has(a.mediator)) {
    links.set(
      a.mediator,
      await MediatorLink.open(a.mediator, holder, peerDid, () => {
        // Forget it, but do not reconnect here: reconnecting on a drop nobody asked about
        // would hold a socket open for a page that may never ask again. The next request
        // opens one.
        links.delete(a.mediator);
      }),
    );
  }
  return { link: links.get(a.mediator), carrier: preferredCarrier(a), advertised: a };
}

/// Drop every link. Called when the identity changes: a socket is authenticated as one
/// transport DID, and a different member is a different party.
export function closeLinks() {
  for (const link of links.values()) link.close();
  links.clear();
}

/// The Ed25519 key a room signs with, for the invitation gate in wasm.
///
/// **Why this crosses the boundary at all.** For a `did:key` or a `did:peer` the gate derives
/// the key from the identifier and ignores whatever is passed — the identifier *is* the key,
/// and taking the caller's word for it would give up the one check wasm can make entirely
/// alone. For a `did:webvh` there is nothing in the identifier to derive from: resolving one
/// means fetching a log over HTTPS and verifying its history, which is I/O, and wasm has
/// none. So this page resolves it, and the resolution is the trust.
///
/// `null` when the method carries its own key, so the gate takes the lexical path and this
/// page's opinion never enters into it.
export async function issuerKey(did) {
  if (did.startsWith("did:key:") || did.startsWith("did:peer:")) return null;
  return await verificationKey(did);
}
