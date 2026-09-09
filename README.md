# Data rooms — demo

A single site where somebody with no wallet, no agent and no account can mint their own
`did:key` in the browser, be admitted to a data room, and read and write records the host
stores but cannot read.

Design note:
[`docs/05-design-notes/data-rooms-demo-site.md`](https://github.com/OpenVTC/verifiable-trust-infrastructure/blob/main/docs/05-design-notes/data-rooms-demo-site.md)
in [OpenVTC/verifiable-trust-infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure),
which is also where `room-host` and `vti-rooms` live. §10 is what building this changed,
including the two predictions that did not survive it.

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

**The two halves of that claim were not equally true, and the gap is what the DIDComm leg
closes.** Working *in* a room is host-only — list, get, put, curate, the epoch chain — and a
host needs nothing but the request: a signed document and a chain the room issued. That half
always worked against any host, from a link. **Admission did not.** It needs the room's
owner, and the only way to reach an owner was this sample's own HTTP catalogue — so the site
could admit you only to a room it was already configured for, which is the opposite of the
claim.

**Set `MEDIATOR_DID` and a room becomes `did:peer:2`**, which carries a service block, so it
can say where its owner listens. The owner then connects to that mediator **as each room**,
and a member who resolved the room's DID reaches the party that can admit them knowing
nothing else. `sample-room/src/bin/join-by-did.rs` is that member, in one argument:

```
cargo run --bin join-by-did -- did:peer:2.Vz6Mk… --at did:peer:2.Vz6Mk…
```

No URL anywhere, no catalogue, no port. It resolves the room (pure computation — no network),
reads the mediator out of it, mints its two identities, asks, verifies the VIC it gets back,
presents it with a KeyPackage, joins the group — and then, given `--at`, seals a record,
writes it, lists the room and opens what comes back. The whole member surface.

`--at` names the **host**, and it has to be said because a room's identifier deliberately does
not name one: a room may be served by several, and a room that named its host could never
move.

It exists so the owner's and the host's carrier arms can be exercised without a browser, and
because two independent members of one protocol is how a shape that only one of them believes
in gets caught.

**The browser does the same.** Paste a room's DID into the site, or follow a
`#/room/<roomDid>` link to a room it holds no keys for, and it runs that ceremony — the same
`@openvtc/pnm-core` and `@openvtc/vti-tsp-js` the wallet extension speaks, bundled into
`web/vendor/didcomm.js`. So the site now admits you to rooms it was never told about, which
is the claim it could not previously make.

### Two carriers, one socket, and the room says which

A room advertises `DIDCommMessaging` **and** `TSPTransport` at its mediator, and a member
takes the better of the two it is offered — TSP where present, DIDComm otherwise.

Driven by the room's document rather than by what happens to work, and that distinction is
the point. A mediator permits **one websocket per DID** and multiplexes both onto it — it
sniffs the TSP magic byte on a binary frame — so a client that always spoke TSP would
usually succeed, and would break against the first owner that served only DIDComm, with
nothing in the room's document having changed to warn it. A second socket is not an
alternative either: the mediator evicts one of the pair as a duplicate channel.

The owner listens through the delivery layer's `DidCommTransport`, whose inbound stream
surfaces both protocols tagged by which they arrived on, and answers on the one it was asked
over. The ceremony is identical either way; only the packing differs, and one difference is
worth naming: DIDComm carries `type` and `thid` around the message, while TSP has no headers
at all, so over TSP the payload is `{ id, type, body }` and carries them itself.

```
cargo run --bin join-by-did -- did:peer:2.Vz6Mk…          # the advertised preference — TSP
cargo run --bin join-by-did -- --tsp did:peer:2.Vz6Mk…    # force it, even if unadvertised
```

### A member holds two identities, and they are not interchangeable

- a **transport identity** (`did:peer:2`) — how the mediator addresses them, and what
  DIDComm's authcrypt proves;
- a **room identity** (`did:key`, minted in wasm) — what the room's credentials name, and
  what signs every document the host authenticates them by.

The VIC has to name the second, because that is the key that will later sign records. But the
second is not what sent the message. So a request carries **both** proofs — the DIDComm
envelope for the transport identity, an `eddsa-jcs-2022` proof inside the body for the room
identity — and the body names the transport DID so the two are bound. Without that last part
a signed request is a bearer artefact: anybody who saw one could send it from their own
transport identity and be handed the room's reply. There is a test per clause.

Admission is **not** a Trust Task, and that is deliberate. `rooms/owner/{invite,
issue-membership,issue-authority}` are real ones and the owner performs all three — but a
Trust Task is an instruction you give *your own* agent. A stranger asking an owner to decide
something is the opposite, and dressing it up as a Trust Task would say the stranger may
instruct the room's agent.

Production mints `did:webvh` rather than either, for a reason neither has: a room's
controller must be able to change, and transferring ownership is a controller change.
`did:peer` encodes its keys in the identifier, so it can never have one.

**`sample-room/` exists so the demo runs standalone**, and for no other reason. It plays one
part that lives elsewhere in a real deployment: the **owner**, who creates a room, admits
people, and keeps its commits so members can catch up. In a real deployment that is a person
with a VTA, driving it from the wallet console or `pnm-cli`.

It is **not** the host. It used to carry a fallback record API for when `room-host` was not
running, and that is gone — records go to the real host and nowhere else, so there is no
longer any path in this demo where something stands in for storage rather than being it.

Over HTTP it now serves exactly two things: the page, and a catalogue of the rooms it happens
to hold. Everything in the trust model — admission, commits, records, the epoch chain — goes
over a mediator. There is **one** admission implementation, and clicking a card runs the same
ceremony as pasting a DID; there used to be a second over this site's own API, and it was the
one a card took, so the common case took the weaker route. Weaker specifically: over HTTP the
asker's DID was a claim, where over the mediator it is proved by the request's own signature
and bound to the connection that carried it.

## Running it

**[GUIDE.md](GUIDE.md) is the walkthrough** — what to type, what to click, how to set up your
own room, and what to look at while you do. This section is the short form.

Two modes. The first is the smaller thing to stand up; the second is the one the design is
about.

### Everything local, over HTTP

```
# the host — the real binary, built from a checkout of
#   github.com/OpenVTC/verifiable-trust-infrastructure
cargo run -p room-host -- \
  --data-dir /tmp/room-host-data \
  --listen 127.0.0.1:8300 \
  --allow-origin http://127.0.0.1:8787

# the owner, and the site
cd sample-room && DEMO_WEB_DIR=../web cargo run
# → http://127.0.0.1:8787
```

The rooms the sample offers are named by `ROOMS_FILE`, or a built-in pair when it is unset —
see [GUIDE.md §3](GUIDE.md#3-set-up-your-own-room). Rooms are `did:key` in this mode, so they
advertise nothing and can only be joined through this sample's own catalogue. That is honest rather than broken: a room pointing at somewhere
nobody listens fails at the join, while a room pointing nowhere says so before you try.

### Over a mediator, with no browser-reachable URL anywhere

Both halves need `--features didcomm`, which is a **cargo** flag and off by default — a host
that is not asked to be reachable opens no socket and mints no identity.

```
# the host. Note: no --allow-origin, so the page cannot reach it over HTTP at all.
cargo run -p room-host --features didcomm -- \
  --data-dir /tmp/room-host-data \
  --listen 127.0.0.1:8300 \
  --mediator-did did:webvh:…:mediator
# → host DID: did:peer:2.Vz6Mk…          ← copy this
```

```
# the owner and the site. MEDIATOR_DID makes each room a did:peer:2 that advertises where
# its owner listens; ROOM_HOST_DID is what members are told about the host.
cd sample-room
MEDIATOR_DID=did:webvh:…:mediator \
ROOM_HOST_DID=did:peer:2.Vz6Mk… \
DEMO_WEB_DIR=../web cargo run
# → listening for did:peer:2.Vz6Mk… at did:webvh:…   (DIDComm + TSP)
```

Now the site admits you to rooms it was never told about — paste a room DID, or follow a
`#/room/<roomDid>?at=<hostDid>` link — and every record operation goes over the mediator. To
prove that last part, check that the browser genuinely cannot reach the host: with no
`--allow-origin`, a `fetch` to `127.0.0.1:8300` from the page fails, and writing a record
still works.

The same ceremony without a browser, which is also the reference implementation:

```
cd sample-room
cargo run --bin join-by-did -- <roomDid> --at <hostDid>
#   --tsp forces TSP even where a room does not advertise it
```

The owner reaches the host by URL while telling members its DID, and that is the shape rather
than an inconsistency: the owner is a server and can open a URL, a browser frequently cannot,
and one host serves both carriers at once with the client choosing.

## What is real, and what is not

**Real.** The `did:key` is minted in the tab by WebCrypto. The MLS group, record sealing
and the epoch key chain are `vti-rooms` itself, compiled to `wasm32-unknown-unknown` — the
same crate the services link, not a re-implementation. The invitation is a signed DTG
credential and the browser checks all six clauses before it will mint a KeyPackage or
accept a Welcome. The host holds ciphertext and has no code path that could read it.

**Also real: the record path never touches a URL.** Set `ROOM_HOST_DID` and members are
given the host's DID instead of its address, and reach it through the same mediator. The
demonstration is that this is not a fallback — start `room-host` with **no `--allow-origin`
at all**, so the page cannot open an HTTP request to it under any circumstances, and sealing,
writing, listing, re-opening and the epoch chain all still work.

What that buys is reach, not authority. A URL address requires the *member* to be somewhere
that can open it; a DID address requires nothing of either side but a mediator they share. A
host on a laptop, behind NAT, or on an origin no browser would be permitted to call is
reached exactly the way a phone is.

Nothing about authorization changes, and that is the design: the presenter comes from the
document's own `eddsa-jcs-2022` proof and the authority from the chain the room issued, so
the same bytes are as authorized over a socket as over a POST. `room-host` runs one
`dispatch` for all three carriers and has a test that they answer identically.

**Deliberately not shown.** The `private` visibility tier. Its subject binding has to be
proved in zero knowledge and the working group has not settled the profile; a demo tier
that quietly behaved like `attributed` would misrepresent it.

## Where the pieces come from

| | |
|---|---|
| `web/vendor/vti_rooms*` | built from `vti-rooms-wasm` — see below |
| `web/vendor/didcomm.js` | `@openvtc/pnm-core`, `@openvtc/vti-didcomm-js`, `@openvtc/vti-tsp-js`, `@noble/curves`, bundled |
| `sample-room/` | `vti-rooms` with the `mls` feature, native |

Both files under `web/vendor/` are **build artifacts, not source** — checked in so the site
stays static files with nothing to install before opening it. Rebuild instructions are below,
and neither is edited by hand. They carry the licences of what they were built from:
Apache-2.0 for the OpenVTC crates and packages, MIT for `@noble/curves`.

This repository is Apache-2.0, matching the stack it demonstrates.

Rebuild the wasm after changing `vti-rooms-wasm`:

```
cargo build -p vti-rooms-wasm --profile wasm-release --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir <this>/web/vendor --out-name vti_rooms \
  target/wasm32-unknown-unknown/wasm-release/vti_rooms_wasm.wasm
```

Rebuild the DIDComm bundle after changing `web/src/transport.js`, which is only the list of
what the demo uses:

```
cd web && npm install && npm run build -- --minify
```

The site itself stays static files — `npm` is build-time only, and nothing it produces is
written by hand here. A demo that re-implemented DIDComm would be demonstrating the
re-implementation.
