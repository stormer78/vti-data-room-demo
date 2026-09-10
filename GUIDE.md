# Running the demo, and setting up a room

The [README](README.md) says what this is and why it is shaped the way it is. This says what
to type.

Three processes. Each is a separate party in the design, which is why there are three:

| | who | what it is in a real deployment |
|---|---|---|
| **host** | stores ciphertext it cannot read | a VTC, or the `room-host` binary |
| **owner** | creates rooms and admits people | a person with a VTA |
| **the site** | a client, and nothing else | a web page |

The owner and the site are served by one process here only because a demo needs a front door.
Nothing in the trust model joins them.

---

## 1. Start it

You need a checkout of
[OpenVTC/verifiable-trust-infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
for the host, and this repository for the rest.

**Terminal 1 — the host.** From the VTI checkout:

```
cargo run -p room-host -- \
  --data-dir /tmp/room-host-data \
  --listen 127.0.0.1:8300 \
  --allow-origin http://127.0.0.1:8787
```

**Terminal 2 — the owner and the site.** From this repository:

```
cd sample-room
DEMO_WEB_DIR=../web cargo run
```

Open <http://127.0.0.1:8787>.

---

## 2. Walk through it

**Mint a key.** "Mint a did:key". It is generated inside WebAssembly and the page never sees
the private half. It lives in this browser and nowhere else — clearing site data destroys it,
and nobody can reissue it. That is the point and also the risk, so do not put anything in
here you would mind losing.

**Join a room.** Pick one and press *Ask to join*. Section 3 fills in with both halves of the
ceremony: what the owner did, and what your browser checked before acting on any of it. Read
it once. Admission is a two-party act and this is the only place you will see both sides.

**Write a record.** Give it a key and a body, and *Seal & write*. It is encrypted in the tab
before it leaves. Expand *what the host has* underneath to see what was actually stored — the
ciphertext, the nonce, and the epoch it was sealed under. No part of that opens without the
group key, which the host does not hold.

**Be somebody else.** Switch to `bob` — top right — and mint a second key. This is not a view
filter; it is a different person, with their own key, their own MLS leaf and their own
credentials. Join the same room and read what `alice` wrote *before bob existed*.

That last part is the epoch key chain doing its job. Every membership change advances the
room's epoch, and each *rung* seals the outgoing epoch's key under the incoming one — so a
member who arrives at epoch 5 can walk backwards and read epoch 2. Watch **earliest readable**
drop to 1 when the rungs arrive.

Backwards only, and that is the property rather than a limit: a rung lets you descend from a
key you hold, never climb to one you do not. Which is what makes removal work — somebody
removed at epoch 7 cannot reach epoch 8.

**Get refused.** Retract a record in each room. The Workshop grants `curate` and the Library
does not, so the same button works in one and is refused in the other — and refused *in your
own tab*, before any request is made, because `attenuate` will not widen what the room gave
you.

That distinction is worth pausing on. "You were never given this" and "the host disagreed" are
different sentences, and only the first can be answered by asking the owner.

**Hand somebody the link.** Section 3 shows the room's address:

```
http://127.0.0.1:8787/#/room/<roomDid>?at=<host>
```

A room is addressed, never configured. That link works in any browser holding keys for the
room, against a host the site has never seen.

---

## 3. Set up your own room

The two rooms above are only what the sample ships with. Write a JSON file:

```json
[
  { "id": "board", "label": "Board papers — read only", "grants": ["read"] },
  { "id": "deal",  "label": "Project Northwind",        "grants": ["read", "write", "curate"] }
]
```

```
ROOMS_FILE=./my-rooms.json DEMO_WEB_DIR=../web cargo run
```

- **`id`** is a slug for the catalogue. It is *not* the room's identifier — the room mints a
  DID at startup, and that is what every credential, every record and every link means by
  "room". The slug never reaches the host.
- **`grants`** is the authority the room confers on a member it admits: `read`, `write`,
  `curate`, `admin`. This is the whole of what makes two rooms different. A member of the
  read-only room above who tries to write is refused by their own key holder — the room never
  conferred it, so there is nothing to narrow.

A grant no host understands is refused at startup rather than becoming a credential that
fails at first use, somewhere else entirely.

**Rooms are minted fresh on each start.** Their DIDs change, so links from a previous run stop
resolving. That is a property of this sample rather than of rooms: a real room is a
`did:webvh` whose controller can change, which is what makes ownership transferable.

---

## 4. Over a mediator — no browser-reachable URL anywhere

Everything above still has the browser opening a URL to the host. It does not need to.

A room advertises the mediator its owner listens on, so the site can reach a room it was never
told about. The host can advertise one too. Then admission, commit delivery and every record
operation go over that mediator, and **no part of the trust model needs a URL** — which
matters because a host on a laptop, behind NAT, or on an origin no browser may call is
reachable exactly the way a phone is.

You need a mediator DID. **Terminal 1**, with no `--allow-origin` at all, so the page cannot
reach the host over HTTP even if it wanted to:

```
cargo run -p room-host --features didcomm -- \
  --data-dir /tmp/room-host-data \
  --listen 127.0.0.1:8300 \
  --mediator-did did:webvh:…:mediator
# → host DID: did:peer:2.Vz6Mk…        ← copy this
```

**Terminal 2:**

```
cd sample-room
MEDIATOR_DID=did:webvh:…:mediator \
ROOM_HOST_DID=did:peer:2.Vz6Mk… \
DEMO_WEB_DIR=../web cargo run
# → listening for did:peer:2.Vz6Mk… at did:webvh:…   (DIDComm + TSP)
```

Now paste a **room DID** into "Or join one this site has never heard of". The site resolves
it — pure computation, no network — reads the mediator out of it, connects, and runs the whole
admission ceremony against an owner it had never heard of.

To convince yourself the record path really is over the mediator, open the console and try to
reach the host directly. It fails, and writing a record still works:

```js
await fetch("http://127.0.0.1:8300/trust-tasks", {method: "POST"})   // TypeError: Failed to fetch
```

`--features didcomm` is a **cargo** flag and off by default. A host that is not asked to be
reachable opens no socket and mints no identity.

### The host's identity, and where it comes from

The host above **mints its own** `did:peer:2` and keeps it under `--data-dir`. That is the
right thing for a laptop: the identifier encodes both its keys and its mediator, so
`?at=<did>` is a complete address a member resolves by computation, with nothing to look up.

It is the wrong thing for a room a VTA governs, for one reason: a `did:peer` encodes its keys
in the identifier, so its controller can never change. A host that cannot rotate a key or hand
itself over is a host you can never recover. §4a is the other way round — the VTA holds the
identity and this host fetches it.

### Without a browser

The same ceremony, and the reference implementation both sides were written against:

```
cd sample-room
cargo run --bin join-by-did -- <roomDid> --at <hostDid>
```

It resolves the room, mints its two identities, asks to join, verifies the invitation it gets
back, presents it with a KeyPackage, joins the group, then seals a record, writes it, lists
the room and opens what comes back. No URL anywhere in the run. `--tsp` forces TSP even where
a room does not advertise it.

---

## 4a. A host a VTA governs

Everything above runs a host that answers to nobody: it mints its own identity and serves
whatever rooms present valid credentials. That is the whole point of the design — a host
authorises against the room's credentials, not against anything it stores — and it is why the
demo works with no VTA at all.

A deployment usually wants the other arrangement: the host has an identity **the VTA holds**,
in a context an operator controls, so its keys can be rotated and its DID can outlive it.
Three steps, and the order matters.

### 1. Give the context a DID

This is the step nobody guesses, and the one the room-creation form does not explain: it asks
for a HOST DID without saying where one comes from. It comes from your VTA.

From the wallet extension, on the **New room** form, press **Mint one** beside HOST DID. It
mints with the `room-host` template — a DIDComm service at your mediator and a REST service at
the host's URL — and fills the field in.

Or from a terminal:

```
pnm did-mgmt dids create --context rooms --server <SERVER_ID> \
        --label "room host" --mediator-service
```

`--server` is a DID-hosting server you have registered (`pnm did-mgmt servers list`). Add
`--path <name>` to choose the name it is published under; omit it and the server assigns one.
`--mediator-service` is not optional in practice: members reach a host by resolving its DID,
so a host DID that advertises no service block is one nobody can dial.

### 2. Enrol the host, and grant it

```
cargo run -p room-host --features didcomm,onboarding -- \
  --data-dir /tmp/room-host-data \
  --listen 127.0.0.1:8300 \
  --mediator-did did:webvh:…:mediator \
  --vta-did did:webvh:…:agent \
  --vta-context rooms
```

The first run **stops**, and prints a throwaway `did:key` with the command to authorize it.
That stop is deliberate: a host that cannot be authorized for anything the VTA governs has
nothing to serve, and starting anyway would look like it was working.

Grant it, using the line it printed:

```
pnm acl create --did did:key:z6Mk… --role application --contexts rooms
```

**`application`, not admin.** A host holds ciphertext it cannot read and no room keys, so it
needs to act in the context and needs no authority over it. That grant is also exactly what
lets it read its own keys and nothing else.

### 3. Start it again

```
# same command as step 2
# → host DID: did:webvh:…:rooms:host      ← the VTA's DID, not one it minted
```

The throwaway is rotated away on that first successful connect, so a DID that travelled
through a chat window does not stay live. Then the host fetches the context's DID and its keys
and serves as that.

Use that DID as the HOST DID when you create the room, and as `?at=` in the site.

### What happens when the VTA is down

The host caches the identity it fetched and comes up on it, logging that it did. Without that,
a VTA outage would stop every host enrolled with it — a far larger blast radius than the
outage itself, for a process that is only storing ciphertext.

### If the context has no DID

You will see this, and it means step 1 was skipped:

```
Context `rooms` on did:webvh:…:agent has no DID, so there is no identity for this host
to serve as.
```

It prints the command to fix it. The host does not create one for itself: it enrols with an
`application` role, and minting a DID in a context needs an admin — deliberately, because
letting a host mint identities in your context is more authority than the job needs.

## 5. Fronting a real room — a standalone host, or a VTC

Nothing above is specific to this sample. The site is a client, and both kinds of host serve
the same surface.

**A standalone `room-host`** is what §1 and §4 already run. Point `?at=` at its URL or its DID
and the site cannot tell the difference from the sample's.

**A VTC data room** works the same way, and needs nothing from this repository. A VTC serves
the whole `rooms/*` family — `records/{put,get,list,curate}`, `epoch/chain`, `create`,
`owner/{claim,transfer}` — through the same dispatch spine and the same delivery layer, over
REST, DIDComm **and** TSP.

The two hosts agree by construction rather than by care: both build every response through the
same `vti_rooms::wire` constructors, and those types are checked against their schemas in
`vti-rooms/tests/schema_conformance.rs`. They cannot drift about a record's shape without the
shared type changing under both.

Which is exactly why the one place they *did* disagree was the one place no shared type
reached — how a TSP reply is framed, where each host wrote its own send path. `room-host`
wrapped the document; the VTC sent it bare. That is fixed, and the bare document is the wire
form ([VTI #1383](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1383)).

So:

```
#/room/<roomDid>?at=https://vtc.example        # over HTTPS — the VTC needs your origin allowed
#/room/<roomDid>?at=did:webvh:…:vtc            # over its mediator — nothing to allow
```

Two things had to be true for that second line, and both are now:

- **The site resolves `did:webvh`.** It used to resolve `did:peer` only, so it could dial the
  rooms this sample mints and nothing else — and a production room is a `did:webvh`, as is a
  VTC.
- **A `did:webvh` room's invitation can be verified in the browser.** The gate in wasm derives
  a key from a `did:key` or a `did:peer` identifier and has no way to resolve a log; the page
  resolves it and passes the key in
  ([VTI #1382](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1382)).

### What still has to come from somewhere else

**Admission.** Working *in* a room needs only the host. Being *let into* one needs the room's
owner to decide, and a VTA has no surface for a stranger to ask — `rooms/owner/*` are
instructions an owner gives their own agent, not requests a stranger makes. `sample-room`
implements that missing surface, which is the honest description of what it is for.

So a VTC room can be fronted today by a member who **already holds** its membership and
authority credentials — the site will open it, read it, write to it and walk its epoch chain.
Getting those credentials in the first place still goes through an owner that speaks the
admission protocol, and no VTA does yet.

---

## When something does not work

**"advertises no mediator, so there is nowhere to ask to join"** — the room is a `did:key`.
Start the owner with `MEDIATOR_DID` set; without it a room has no service block and cannot say
where anybody listens.

**A record lists but will not open** — you are behind. Every membership change advances the
epoch, and a member who missed a commit can open nothing sealed after it. The site catches up
on open; if it cannot reach the owner, it cannot. This failure reads as corruption and is not.

**The host prints a throwaway DID and stops** — it is enrolled with a VTA (`--vta-did`) and
waiting to be authorized. That is not a failure; it is the one step that cannot be automated,
because it is a person deciding this host may act in their context. Run the `pnm acl create`
line it printed, then start it again. See §4a.

**"Context `…` has no DID, so there is no identity for this host to serve as"** — the context
exists and the host is granted on it, but nobody has minted a DID for it. §4a step 1, or the
**Mint one** button beside HOST DID in the wallet's New room form.

**The host serves a `did:peer` when you expected a `did:webvh`** — it was started without
`--vta-did`, or without the `onboarding` cargo feature, so it minted its own identity rather
than fetching the VTA's. Both are needed: `--features didcomm,onboarding`.

**The host refuses to start, naming a 1000-byte limit** — its mediator's DID is too long to
embed. A `did:peer:2` carries its services inside the identifier, so a `did:peer` mediator
does not fit. Use one with a short DID; a `did:webvh` leaves plenty of room.

**The browser cannot reach the host** — if you are running the HTTP mode, the host needs
`--allow-origin http://127.0.0.1:8787`. If you are running the mediator mode, it is not
supposed to, and records should work anyway.
