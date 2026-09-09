# Data rooms — demo

A single site where somebody with no wallet, no agent and no account can mint their own
`did:key` in the browser, be admitted to a data room, and read and write records the host
stores but cannot read.

Design note: `verifiable-trust-infrastructure`,
`docs/05-design-notes/data-rooms-demo-site.md`.

## Two things, and the boundary between them is the point

```
web/           the site — a CLIENT, and nothing else
sample-room/   optional local infrastructure, so the site has something to point at
```

**`web/` does not host rooms.** It holds a key, joins rooms, and gives you a way to work
inside one. A room is addressed, never configured:

```
#/room/<roomDid>?at=<host url>
```

Paste one of those and the site works against a room it has never seen, on a host it does
not know — provided you hold credentials for it. That is the whole of "one site, any number
of rooms", and it only stays true if the site has no special path for the room shipped
beside it.

**The two halves of that claim are not equally true, and the difference is the honest
boundary of what this demonstrates.** Working *in* a room is host-only — list, get, put,
curate, the epoch chain — and a host needs nothing but the request: a signed document and a
chain the room issued. So that half works against any host, from a link. **Admission does
not.** It needs the room's owner, who is reachable over DIDComm at the mediator the room
advertises — and a `did:key` room advertises nothing, because a `did:key` has no service
block.

**Set `MEDIATOR_DID` and the sample's rooms become `did:peer:2`**, which can carry a
service block and so can advertise where their owner listens. Both sides already verify
such a room with no network — `vta-sdk`'s verifier and the browser's invitation gate both
resolve `did:peer` by computation. What is *not* built is the leg that uses it: the browser
does not yet speak DIDComm, so an advertised mediator is a true statement nobody acts on.
Until it does, you can be handed a room you already hold keys for, but you cannot be let
into one the site was not told about.

Production mints `did:webvh` rather than either, for a reason neither has: a room's
controller must be able to change, and transferring ownership is a controller change.
`did:peer` encodes its keys in the identifier, so it can never have one.

**`sample-room/` exists so the demo runs standalone**, and for no other reason. It plays
the two parts that live elsewhere in a real deployment:

- the **host**, which stores ciphertext it cannot read — in a real deployment a VTC, or
  the standalone `room-host` binary;
- the **owner**, who creates the room and admits people — in a real deployment a person
  with a VTA, using the wallet console or `pnm-cli`.

If the site ever needs to know which of the two it is talking to, the demo has stopped
demonstrating anything. The interface is the same either way.

## Running it

```
# the host — the real binary, from the VTI workspace
room-host --data-dir /tmp/room-host-data --listen 127.0.0.1:8300 \
          --allow-origin http://127.0.0.1:8787

# the owner, and the site
cd sample-room && DEMO_WEB_DIR=../web cargo run
# → http://127.0.0.1:8787
```

Add `MEDIATOR_DID=did:key:z6Mk…` to make the rooms `did:peer:2` and advertise it. Without
it they are `did:key` and advertise nothing, which is honest rather than broken — a room
pointing at somewhere nobody listens fails at the join, while a room pointing nowhere says
so before you try.

## What is real, and what is not

**Real.** The `did:key` is minted in the tab by WebCrypto. The MLS group, record sealing
and the epoch key chain are `vti-rooms` itself, compiled to `wasm32-unknown-unknown` — the
same crate the services link, not a re-implementation. The invitation is a signed DTG
credential and the browser checks all six clauses before it will mint a KeyPackage or
accept a Welcome. The host holds ciphertext and has no code path that could read it.

**Not yet.** The authority chain. A real host takes two things from a request — the
presenter, from the document's own `eddsa-jcs-2022` proof, and a chain verified against
credentials the room issued — and until the browser can mint an authority presentation it
cannot speak that surface. Until then `sample-room` serves a plain HTTP record API, which
is the one place this demo is standing in for something rather than being it.

**Deliberately not shown.** The `private` visibility tier. Its subject binding has to be
proved in zero knowledge and the working group has not settled the profile; a demo tier
that quietly behaved like `attributed` would misrepresent it.

## Where the pieces come from

| | |
|---|---|
| `web/vendor/vti_rooms*` | built from `vti-rooms-wasm` — see below |
| `sample-room/` | `vti-rooms` with the `mls` feature, native |

Rebuild the wasm after changing `vti-rooms-wasm`:

```
cargo build -p vti-rooms-wasm --profile wasm-release --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir <this>/web/vendor --out-name vti_rooms \
  target/wasm32-unknown-unknown/wasm-release/vti_rooms_wasm.wasm
```
