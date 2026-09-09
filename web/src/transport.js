// The member's **transport identity**, and the DIDComm connection it opens.
//
// This is the half of a member that lives in JavaScript. The other half — the room
// identity, which signs everything a room or a host authenticates — lives in wasm and its
// secret never crosses into this file.
//
// # Why a member holds two keys
//
// Not a design preference: the two jobs need different key material and one of them cannot
// be done where the other is. DIDComm's authcrypt needs an X25519 key *in the caller's
// hands* — the browser derives it from an Ed25519 secret it must therefore hold in the
// page. The room identity signs credentials and records, and the whole point of putting it
// in wasm was that its secret never appears in a JavaScript heap or a `localStorage`
// string. Giving the transport its own throwaway key is what lets both stay true.
//
// So the transport identity is deliberately disposable — mint one per session, and losing
// it costs nothing. The room identity is the one worth keeping.
//
// Everything here is `@openvtc/pnm-core` and `@openvtc/vti-didcomm-js`: the same DIDComm
// the wallet extension speaks, not a demo re-implementation. This file is only the list of
// what the demo uses; esbuild turns it into `web/vendor/didcomm.js`.

export { createDidPeer2 } from "@openvtc/pnm-core/did";
export { buildHolder } from "@openvtc/pnm-core/store";
export {
  connectMediatorSession,
  resolveKeyAgreement,
  packAuthcryptJson,
  wrapForward,
} from "@openvtc/pnm-core/didcomm";
export { didPeer } from "@openvtc/vti-didcomm-js";
export { ed25519, x25519 } from "@noble/curves/ed25519.js";
