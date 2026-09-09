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

## When something does not work

**"advertises no mediator, so there is nowhere to ask to join"** — the room is a `did:key`.
Start the owner with `MEDIATOR_DID` set; without it a room has no service block and cannot say
where anybody listens.

**A record lists but will not open** — you are behind. Every membership change advances the
epoch, and a member who missed a commit can open nothing sealed after it. The site catches up
on open; if it cannot reach the owner, it cannot. This failure reads as corruption and is not.

**The host refuses to start, naming a 1000-byte limit** — its mediator's DID is too long to
embed. A `did:peer:2` carries its services inside the identifier, so a `did:peer` mediator
does not fit. Use one with a short DID; a `did:webvh` leaves plenty of room.

**The browser cannot reach the host** — if you are running the HTTP mode, the host needs
`--allow-origin http://127.0.0.1:8787`. If you are running the mediator mode, it is not
supposed to, and records should work anyway.
