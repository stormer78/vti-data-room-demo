// **Admission** — asking a room's owner to let you in.
//
// The transport is [`./carrier.js`]; this is only the conversation. What it does that a
// record request does not is ask somebody to *decide* something.
//
// # Why this is not a Trust Task
//
// `rooms/owner/{invite,issue-membership,issue-authority}` are real Trust Tasks and the owner
// performs all three — but a Trust Task is an instruction you give **your own** agent,
// authorised by your control of it. `vta-service` gates those three on `CredentialWrite` and
// never asks who the subject is. A stranger asking an owner to decide is the opposite, and
// calling it a Trust Task would say the stranger may instruct the room's agent, which is
// exactly what must not be true.
//
// Records are the other case and go the other way — a Trust Task, over the binding that
// already exists for one. The difference is not the carrier; it is who is being asked.
//
// # Two proofs, and the binding between them
//
// A member holds a transport identity (how the mediator addresses them) and a room identity
// (what credentials name, and what signs records later). The VIC has to name the second,
// because that is the key that will sign; but the second is not what sent the message. So a
// request carries **both** proofs and the owner checks they agree: the envelope proves the
// transport DID sent it, an `eddsa-jcs-2022` proof inside the body proves the room DID
// authored it, and the body names the transport DID so the two are bound.
//
// Without that last part a signed request is a bearer artefact — anybody who saw one could
// send it from their own connection and be handed the invitation.

export const REQUEST_INVITATION = "https://dataroom.demo/admission/0.1/request-invitation";
export const INVITATION = "https://dataroom.demo/admission/0.1/invitation";
export const REQUEST_ADMISSION = "https://dataroom.demo/admission/0.1/request-admission";
export const ADMITTED = "https://dataroom.demo/admission/0.1/admitted";

/// Build the body of a request and have the **room** identity sign it.
///
/// Signed in wasm, so the key that will later sign records is the key that asks — and its
/// secret never reaches this file.
export function signedRequest(identity, roomDid, transportDid, extra = {}) {
  const body = { roomDid, memberDid: identity.did, transportDid, ...extra };
  return JSON.parse(identity.signDocument(JSON.stringify(body)));
}

/// Ask for an invitation, and get one back.
export async function requestInvitation(link, carrier, roomDid, identity) {
  const reply = await link.askProtocol(
    roomDid,
    carrier,
    REQUEST_INVITATION,
    signedRequest(identity, roomDid, link.transportDid),
  );
  if (reply.type !== INVITATION) throw new Error(`expected an invitation, got ${reply.type}`);
  return reply.body;
}

/// Present the invitation with a key package, and be admitted.
export async function requestAdmission(link, carrier, roomDid, identity, keyPackage, invitation) {
  const reply = await link.askProtocol(
    roomDid,
    carrier,
    REQUEST_ADMISSION,
    signedRequest(identity, roomDid, link.transportDid, { keyPackage, invitation }),
  );
  if (reply.type !== ADMITTED) throw new Error(`expected admission, got ${reply.type}`);
  return reply.body;
}
