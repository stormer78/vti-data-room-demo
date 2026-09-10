# Deploying the demo site, and running a room

[GUIDE.md](GUIDE.md) is for running this on a laptop. This is for putting it somewhere other
people can reach, behind a load balancer that terminates TLS.

Read the caveat at the bottom before you put anything in a room you would mind losing.

---

## What you are deploying

Three things, and only one of them faces the internet:

| | reachable from | why |
|---|---|---|
| **the site + owner** (`sample-room`) | the load balancer | serves the page and admits people |
| **the host** (`room-host`, or a VTC) | **nothing** | reached through a mediator |
| **a mediator** | both, outbound | you already have one, or run one |

The host needs no ingress at all. It dials the mediator outbound, and members reach it the
same way. That is the arrangement worth deploying — see *Why the mediator mode* below.

---

## 1. TLS, and why it is not optional

Terminate TLS at the balancer and forward to the owner on `:8787`.

```
https://rooms.example.com   →   LB (TLS)   →   sample-room :8787
```

**HTTPS is a functional requirement, not hygiene.** The page derives key material and talks to
a mediator over `wss://`; browsers restrict both on a plaintext origin, and a page served over
`http://` will fail in ways whose error messages name the content policy rather than the
cause.

The balancer needs:

- **WebSocket upgrade** left alone if you ever proxy mediator traffic. In the arrangement
  here you do not — the browser connects to the mediator directly — but a balancer that
  strips `Upgrade` headers wholesale will bite you later.
- **A stable hostname.** Keys live in `localStorage`, which is scoped to the origin. Move the
  site to a different hostname and every member's key is gone, with no recovery. This is the
  same property the site warns about on screen, and a deployment can breach it by accident in
  a way a laptop cannot.
- No special path rules. Everything is under `/`, and `/api/rooms` is the only endpoint.

---

## 2. The owner and the site

```
LISTEN=0.0.0.0:8787 \
MEDIATOR_DID=did:webvh:…:mediator \
ROOM_HOST_DID=did:peer:2.Vz6Mk… \
ROOMS_FILE=/etc/rooms.json \
DEMO_WEB_DIR=/srv/web \
  dataroom-sample-room
```

| | |
|---|---|
| `LISTEN` | **Set it.** Defaults to `127.0.0.1:8787`, which inside a container is unreachable from the balancer — and the symptom is a health check that never passes rather than an error the process can print. |
| `MEDIATOR_DID` | Makes each room a `did:peer:2` advertising where its owner listens. Without it rooms are `did:key`, advertise nothing, and can only be joined through this site's own catalogue. |
| `ROOM_HOST_DID` | What members are told about the host. Printed by `room-host` at startup. |
| `ROOMS_FILE` | The rooms to offer — [GUIDE §3](GUIDE.md#3-set-up-your-own-room). |
| `DEMO_WEB_DIR` | The static files. |

Egress: outbound HTTPS and WSS to the mediator. Nothing else.

**Health check** `GET /api/rooms`. It returns the catalogue as JSON once the rooms are minted
and registered, which is the first moment the site is useful — so it fails while the owner is
still starting rather than reporting ready too early.

### Serving the static files elsewhere

`web/` is static and can go on a CDN or object store instead. Two things must hold: it is the
**same origin** as `/api/rooms` (the site fetches it as a relative path, and a cross-origin
catalogue is both a CORS problem and a `localStorage` split), and `web/vendor/*` is served
with its real content type. `application/wasm` for the `.wasm` is not strictly required —
wasm-bindgen falls back to `WebAssembly.instantiate` and warns in the console — but the
fallback buffers the whole 2.4 MB module before compiling it, which is the difference between
a page that appears quickly and one that sits on "Loading…" for a beat on every visit.

---

## 3. The host

```
room-host \
  --data-dir /var/lib/room-host \
  --listen 127.0.0.1:8300 \
  --mediator-did did:webvh:…:mediator
# → host DID: did:peer:2.Vz6Mk…      ← this is ROOM_HOST_DID above
```

Built with `--features didcomm`; it is off by default, so a host that is not asked to be
reachable opens no socket and mints no identity.

**No ingress, and no `--allow-origin`.** Members reach it through the mediator. The `--listen`
port is for you — health checks and anything local — and can stay on loopback.

`--data-dir` **must be durable**. It holds the records *and* `host-identity.json`, which is
the DID members have saved. Lose it and every saved address points at a host that no longer
exists; the failure presents as a timeout, which reads as "the host is down" rather than "the
host is now somebody else". It holds a private key, so it is created owner-only — keep it that
way.

One constraint that will refuse to start rather than half-work: **the mediator's DID must be
short enough to embed**. A `did:peer:2` carries its services inside the identifier, so a
`did:peer` mediator does not fit under the 1000-byte resolver limit. A `did:webvh` leaves
plenty of room. The host names the limit and stops.

### Or give the host a VTA identity

The host above mints its own `did:peer:2`. For a deployment, prefer an identity the VTA holds:
its keys can be rotated and its DID outlives the process, neither of which a `did:peer` can do
— the identifier encodes the keys, so the controller can never change.

```
room-host --data-dir /var/lib/room-host \
          --listen 127.0.0.1:8300 \
          --mediator-did did:webvh:…:mediator \
          --vta-did did:webvh:…:agent \
          --vta-context rooms \
          --secrets /etc/room-host/secrets.toml
```

Built with `--features didcomm,onboarding`. The first start prints a throwaway `did:key` and
**exits**; grant it `application` on the context (`pnm acl create --did … --role application
--contexts rooms`) and start it again. It then fetches the context's DID and keys and serves
as that. GUIDE §4a is the walkthrough, including minting the context's DID first.

Two operational notes:

- **`--secrets` matters more here.** The cached VTA identity is kept in the same store as a
  self-minted one, so without a `[secrets]` table it is a cleartext file on whatever volume
  the container was given. The host warns once at startup.
- **A VTA outage does not stop the host.** It comes up on the cached identity and logs that it
  did. Losing every host when the VTA blinks would be a far larger blast radius than the
  outage, for a process that only stores ciphertext.

### Or point at a VTC instead

A VTC serves the same `rooms/*` surface over the same carriers, and the site cannot tell the
difference — [GUIDE §5](GUIDE.md#5-fronting-a-real-room--a-standalone-host-or-a-vtc). Set
`ROOM_HOST_DID` to the VTC's DID, or `?at=https://vtc.example` for the REST path, in which
case the VTC needs your site's origin in its CORS configuration.

---

## Why the mediator mode

You can run the host with `--allow-origin https://rooms.example.com` and have the browser
reach it over HTTPS directly. It works, and it costs you: a second public hostname, a second
certificate, a second thing in the balancer, and a CORS policy to keep in step with the site's
origin.

Through a mediator the host needs none of that. It can sit on a private subnet, behind NAT, or
on a laptop, and a member reaches it exactly the way they reach a phone. Which is also the
property the demo exists to show, so running it the easy way and the honest way are the same
thing here.

---

## Before you put anything real in it

**Rooms do not survive a restart.** The owner keeps rooms, their identities, group state,
commits and spent invitations in memory. Restart it and the rooms are minted afresh with new
DIDs: every link breaks, every member's credentials name a room that no longer exists, and the
records still on the host are orphaned under the old identifier. The host persists; the owner
forgets.

That is deliberate — `sample-room` stands in for a party that belongs in a VTA, and
persistence belongs there rather than here — but it means this deployment is for showing
people how data rooms work, not for keeping anything.

Three more, in the order they will matter:

- **The owner admits anyone who asks.** It is stated on screen, and it means there is no access
  control on joining. Do not deploy this where the room list itself is sensitive.
- **Keys live in one browser.** Clearing site data destroys them and nobody can reissue them.
- **The `private` visibility tier is not implemented.** The host cannot read a record, but on
  `attributed` it does learn which member wrote each one.
