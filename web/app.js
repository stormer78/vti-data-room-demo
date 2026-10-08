// The two-person data-room demo.
//
// Alice and Bob each run in this tab as a separate person: their own `did:key` minted and held
// in wasm, their own transport identity and mediator socket, their own MLS leaf. Nothing is
// shared between the two columns except the room they both point at — which is the point.
// When one writes, the other sees it only because it went to the room's host as ciphertext and
// came back, and only opens because their own key holder can derive that epoch's key.
//
// The mechanisms are the classic page's (`classic.html`), regrouped per person: admission,
// the invitation gate, sealing, the epoch chain and commit catch-up are unchanged.

import init, { mintKeyPackage, verifyInvitation, Identity, RoomMember } from "./vendor/vti_rooms.js";
import { requestAdmission, requestCommits, requestInvitation } from "./admission.js";
import { advertised, closeLinks, issuerKey, linkTo, mintTransportIdentity } from "./carrier.js";

await init();

const TT = "https://trusttasks.org/spec/rooms";
const LIST = `${TT}/records/list/0.1`;
const GET = `${TT}/records/get/0.1`;
const PUT = `${TT}/records/put/0.1`;
const CURATE = `${TT}/records/curate/0.1`;
const CHAIN = `${TT}/epoch/chain/0.1`;
const POLL_MS = 4000;

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[<>&"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" })[c]);
const short = (did, n = 18) => (did && did.length > n + 6 ? `${did.slice(0, n)}…${did.slice(-4)}` : did ?? "");
const b64u = {
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)),
};
const bytesOf = (b64) => Math.floor((String(b64 ?? "").replace(/=+$/, "").length * 3) / 4);
const ago = (iso) => {
  if (!iso) return "";
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : new Date(iso).toLocaleString();
};

// localStorage, as the classic page: a demo's key snapshots. Per origin, per browser.
const S = {
  get: (k) => { try { return JSON.parse(localStorage.getItem(k) ?? "null"); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
  del: (k) => { try { localStorage.removeItem(k); } catch {} },
};

// ── timeline ──────────────────────────────────────────────────────────────────
// One chronological story across both people, the owner and the host — what actually moved,
// and who could read it.
const events = [];
function story(actor, text, detail = "") {
  events.unshift({ actor, text, detail, at: new Date() });
  if (events.length > 60) events.pop();
  renderTimeline();
}
function renderTimeline() {
  $("timeline").innerHTML = events.length
    ? events.map((e) => `<li class="ev ev-${e.actor}">
        <span class="dot"></span>
        <div><div>${e.text}</div>${e.detail ? `<div class="ev-detail">${e.detail}</div>` : ""}</div>
        <time>${e.at.toLocaleTimeString()}</time></li>`).join("")
    : `<li class="empty">Nothing yet. Create Alice's key to begin.</li>`;
}

// ── the rooms this page knows about ───────────────────────────────────────────
// The catalogue is only a convenience — the sample's own list. Any room DID works the same.
let catalogue = [];
let roomDid = S.get("dr2:room");
const roomInfo = () => catalogue.find((r) => r.roomDid === roomDid);

// What the host has stored for the current room, as last returned to either member's read.
const hostRows = new Map();

// ── a person ──────────────────────────────────────────────────────────────────
class Person {
  constructor(name, label) {
    this.name = name;
    this.label = label;
    const saved = S.get(this.k("identity"));
    this.identity = saved ? Identity.restore(saved) : null;
    this.transport = null;
    this.member = null;
    this.carrier = null;
    this.records = new Map();
    this.fresh = new Set();
    this.busy = false;
    this.filter = "all";
    this.query = "";
    this.steps = [];
    this.polls = 0;
    this.expanded = new Set();
  }
  k(suffix) { return `dr:${this.name}:${suffix}`; }
  get did() { return this.identity?.did ?? null; }
  held(did = roomDid) { return did ? S.get(this.k("room:" + did)) : null; }
  save(patch) { S.set(this.k("room:" + roomDid), { ...this.held(), ...patch }); }
  spent() { return JSON.stringify(S.get(this.k("spent")) ?? []); }
  markSpent(id) { S.set(this.k("spent"), [...(S.get(this.k("spent")) ?? []), id]); }
  step(text) { this.steps.push(text); renderSteps(this); }

  mint() {
    this.identity = Identity.mint();
    S.set(this.k("identity"), this.identity.snapshot());
    story(this.name, `${this.label} created a key in this browser`,
      `<code>${esc(short(this.did, 28))}</code> — minted inside wasm; the private half never reaches the page`);
  }

  forget() {
    for (const key of Object.keys(localStorage)) if (key.startsWith(`dr:${this.name}:`)) S.del(key);
    if (this.transport) closeLinks(this.transport);
    Object.assign(this, { identity: null, transport: null, member: null, records: new Map(), steps: [] });
    story(this.name, `${this.label}'s key was destroyed`, "and with it every room key — there is no recovery");
  }

  async connect(did) {
    this.transport ??= mintTransportIdentity();
    const found = await linkTo(did, this.transport);
    if (!found) throw new Error(`${short(did)} advertises nowhere to reach it`);
    this.carrier = found.carrier;
    return found;
  }

  /// Admission: ask the room's owner, check the invitation here, join the MLS group.
  async join() {
    const room = roomInfo();
    this.steps = [];
    const where = await advertised(roomDid);
    if (!where) throw new Error("this room advertises no mediator, so there is nowhere to ask");
    this.step(`resolved the room's DID — its owner listens at the mediator`);
    const { link, carrier } = await this.connect(roomDid);
    this.step(`connected over ${carrier === "tsp" ? "TSP" : "DIDComm"} with a fresh transport identity`);

    const { invitation } = await requestInvitation(link, carrier, roomDid, this.identity);
    const vic = JSON.stringify(invitation);
    this.step("the owner sent an invitation");
    story("owner", `The room's owner invited ${this.label}`, "a single-use invitation credential, signed by the room's own key");

    const signingKey = await issuerKey(roomDid);
    const credentialId = verifyInvitation(vic, roomDid, this.did, this.spent(), signingKey);
    this.step("checked it here: issued by this room, to me, signed by its key, unspent");
    const minted = mintKeyPackage(this.did, roomDid, vic, this.spent(), signingKey);
    const { keyPackage } = JSON.parse(minted);
    this.step("minted a one-time MLS key package");

    const out = await requestAdmission(link, carrier, roomDid, this.identity, keyPackage, invitation);
    for (const s of out.steps ?? []) this.step(`owner: ${s}`);
    this.member = RoomMember.join(roomDid, minted, b64u.dec(out.welcome), vic, this.spent(), signingKey);
    this.markSpent(credentialId);
    S.set(this.k("room:" + roomDid), {
      snapshot: this.member.snapshot(), roomDid, host: room?.host,
      membership: out.membership, authority: out.authority, grants: room?.grants ?? [],
    });
    this.step(`joined at epoch ${this.member.epoch} — the group key is held in this tab only`);
    story(this.name, `${this.label} joined <b>${esc(room?.label ?? short(roomDid))}</b> at epoch ${this.member.epoch}`,
      `the room's membership changed, so its epoch advanced; anyone already inside will pick up the commit`);

    const rungs = await this.fetchChain().catch(() => 0);
    if (rungs) this.step(`fetched ${rungs} epoch-key rung(s) from the host, so earlier records open`);
    this.save({ snapshot: this.member.snapshot() });
  }

  /// Re-open a room this browser already holds keys for.
  async open() {
    const held = this.held();
    this.records = new Map();
    this.member = held ? RoomMember.restore(held.snapshot) : null;
    if (!this.member) return;
    await this.catchUp();
    await this.fetchChain().catch(() => 0);
    this.save({ snapshot: this.member.snapshot() });
  }

  /// Apply the commits made since this member last looked — every join is one.
  async catchUp() {
    const before = this.member.epoch;
    const { link, carrier } = await this.connect(roomDid);
    const commits = await requestCommits(link, carrier, roomDid, this.identity, this.member.epoch);
    for (const c of commits) this.member.applyCommit(b64u.dec(c.commit));
    if (commits.length) {
      this.save({ snapshot: this.member.snapshot() });
      story(this.name, `${this.label} applied ${commits.length} membership commit(s): epoch ${before} → ${this.member.epoch}`,
        "someone joined; new records are sealed under the new epoch's key");
    }
    return commits.length;
  }

  async fetchChain() {
    const { links } = await this.hostTask(CHAIN, "read", {});
    if (!links?.length) return 0;
    this.member.addLinks(JSON.stringify(links));
    return links.length;
  }

  /// One signed Trust Task to the room's host, carrying a presentation narrowed to `action`.
  async hostTask(type, action, payload) {
    const held = this.held();
    let presentation;
    try {
      presentation = JSON.parse(this.identity.present(
        JSON.stringify(held.authority), JSON.stringify(held.membership), action, null));
    } catch (e) {
      const err = new Error(e.message ?? String(e));
      err.refusedLocally = true;
      throw err;
    }
    const document = {
      id: `urn:uuid:${crypto.randomUUID()}`,
      type,
      issuedAt: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
      payload: { roomId: roomDid, presentation, ...payload },
    };
    const signed = this.identity.signDocument(JSON.stringify(document));
    const host = held.host;
    if (!host) throw new Error("nothing says where this room's records live");
    let answer;
    if (host.startsWith("did:")) {
      const { link, carrier } = await this.connect(host);
      answer = await link.askTrustTask(host, carrier, JSON.parse(signed));
    } else {
      const res = await fetch(`${host}/trust-tasks`, {
        method: "POST", headers: { "content-type": "application/json" }, body: signed,
      });
      answer = await res.json();
    }
    if (String(answer.type ?? "").includes("trust-task-error")) {
      const p = answer.payload ?? {};
      throw new Error(p.reason ?? p.message ?? p.code ?? "refused");
    }
    return answer.payload;
  }

  /// Turn what the host returned into something to show, opening it with this member's key.
  view(rec) {
    const status = rec.status ?? "active";
    const sealed = rec.sealed ?? null;
    const v = {
      key: rec.key, version: Number(rec.version), status, epoch: sealed?.epoch,
      bytes: bytesOf(sealed?.ciphertext), ciphertext: sealed?.ciphertext ?? "",
      title: rec.key, text: "", author: null, at: null, error: null, needsEpoch: false,
    };
    if (status !== "active" || !sealed) return v;
    try {
      const plain = new TextDecoder().decode(
        this.member.openRecord(rec.key, BigInt(rec.version), JSON.stringify(sealed)));
      try {
        const doc = JSON.parse(plain);
        Object.assign(v, { title: doc.title || rec.key, text: doc.text ?? "", author: doc.author ?? null, at: doc.at ?? null });
      } catch {
        v.text = plain;
      }
    } catch (e) {
      v.error = String(e.message ?? e);
      v.needsEpoch = sealed.epoch > this.member.epoch;
    }
    return v;
  }

  /// Pull the room: list (metadata only), then fetch and open anything new or changed.
  async refresh({ announce = true } = {}) {
    if (!this.member) return;
    if (++this.polls % 4 === 0) await this.catchUp().catch(() => 0);
    const listed = (await this.hostTask(LIST, "read", {})).records ?? [];
    for (const meta of listed) {
      const prev = this.records.get(meta.key);
      const status = meta.status ?? "active";
      if (prev && prev.version === Number(meta.version) && prev.status === status && !prev.error) continue;
      const got = await this.hostTask(GET, "read", { key: meta.key });
      const rec = { ...meta, ...got };
      let v = this.view(rec);
      if (v.needsEpoch) {
        await this.catchUp().catch(() => 0);
        await this.fetchChain().catch(() => 0);
        v = this.view(rec);
      }
      hostRows.set(rec.key, { key: rec.key, version: v.version, status, epoch: v.epoch, bytes: v.bytes, ciphertext: v.ciphertext });
      this.records.set(meta.key, v);
      if (prev || !announce) continue;
      this.fresh.add(meta.key);
      setTimeout(() => { this.fresh.delete(meta.key); renderList(this); }, 4000);
      if (v.author && v.author !== this.name && !v.error) {
        story(this.name, `${this.label}'s browser opened “${esc(v.title)}” from ${esc(cap(v.author))}`,
          `fetched ${v.bytes} bytes of ciphertext from the host and decrypted it with ${this.label}'s own epoch-${v.epoch} key`);
      }
    }
  }

  async write(title, text) {
    await this.catchUp().catch(() => 0);
    const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 32) || "note";
    const key = `notes/${slug}-${crypto.randomUUID().slice(0, 4)}`;
    // Versions are per room, and bound into the ciphertext — seal against the host's answer.
    const listed = (await this.hostTask(LIST, "read", {})).records ?? [];
    const next = listed.reduce((m, r) => Math.max(m, Number(r.version ?? 0)), 0) + 1;
    const body = JSON.stringify({ title, text, author: this.name, at: new Date().toISOString() });
    const sealed = JSON.parse(this.member.sealRecord(key, BigInt(next), new TextEncoder().encode(body)));
    await this.hostTask(PUT, "write", { key, sealed, expectedVersion: 0 });
    story(this.name, `${this.label} sealed “${esc(title)}” and sent it to the host`,
      `encrypted in ${this.label}'s browser under epoch ${sealed.epoch}; the host stored ${bytesOf(sealed.ciphertext)} bytes it cannot read`);
    await this.refresh({ announce: false });
  }

  async retract(key) {
    const title = this.records.get(key)?.title ?? key;
    try {
      await this.hostTask(CURATE, "curate", { key, status: "retracted", reason: "retracted in the demo" });
    } catch (e) {
      if (e.refusedLocally) {
        story(this.name, `${this.label} tried to retract “${esc(title)}” — refused in ${this.label}'s own browser`,
          `this room never granted <code>curate</code>, so ${this.label}'s key holder would not mint a presentation for it. Nothing was sent; the host never saw the attempt.`);
        throw new Error(`this room did not grant you curate — refused before anything was sent`);
      }
      story("host", `The host refused ${this.label}'s retraction`, esc(e.message));
      throw e;
    }
    story(this.name, `${this.label} retracted “${esc(title)}”`,
      "the body is gone from the host; the key and version stay as a tombstone");
    await this.refresh({ announce: false });
  }
}
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

const people = [new Person("alice", "Alice"), new Person("bob", "Bob")];

// ── rendering ─────────────────────────────────────────────────────────────────
function renderRooms() {
  $("room-picker").innerHTML = catalogue.map((r) => `
    <button class="room ${r.roomDid === roomDid ? "on" : ""}" data-room="${esc(r.roomDid)}">
      <span class="room-name">${esc(r.label)}</span>
      <span class="room-did mono">${esc(short(r.roomDid, 22))}</span>
      <span class="grants">${r.grants.map((g) => `<span class="grant">${esc(g)}</span>`).join("")}</span>
    </button>`).join("");
  for (const b of document.querySelectorAll("[data-room]")) b.onclick = () => selectRoom(b.dataset.room);
}

function renderPerson(p) {
  const col = $(`col-${p.name}`);
  const held = p.held();
  const room = roomInfo();
  const status = !p.identity
    ? `<span class="chip">no key yet</span>`
    : !held
      ? `<span class="chip">not a member</span>`
      : `<span class="chip ok">member · epoch ${p.member?.epoch ?? "…"}</span>
         <span class="chip">${(held.grants ?? room?.grants ?? []).join(" · ")}</span>
         ${p.carrier ? `<span class="chip">${p.carrier === "tsp" ? "TSP" : "DIDComm"}</span>` : ""}`;
  col.querySelector(".who-did").innerHTML = p.identity
    ? `<code title="${esc(p.did)}">${esc(short(p.did, 26))}</code>` : "";
  col.querySelector(".who-status").innerHTML = status;

  const act = col.querySelector(".act");
  const mode = !p.identity ? "mint" : !held ? `join:${roomDid}` : `compose:${roomDid}`;
  if (act.dataset.mode !== mode) { act.dataset.mode = mode; act.innerHTML = ""; }
  if (!p.identity) {
    act.innerHTML = `<button data-do="mint">Create ${p.label}'s key</button>
      <p class="hint">A <code>did:key</code> minted inside WebAssembly. The private key never reaches JavaScript.</p>`;
  } else if (!held) {
    act.innerHTML = room
      ? `<button data-do="join">${p.label}: ask to join ${esc(room.label)}</button>
         <p class="hint">Asks the room's owner over the mediator. The owner — not this site — decides.</p>`
      : `<p class="hint">Pick a room above.</p>`;
  } else if (!act.querySelector("textarea")) {
    act.innerHTML = `<input class="c-title" placeholder="Title" maxlength="80">
      <textarea class="c-text" placeholder="Write something only room members can read…"></textarea>
      <div class="row"><button data-do="write">Seal &amp; share</button>
      <span class="hint">Encrypted here, before it leaves ${p.label}'s browser.</span></div>`;
  }
  for (const b of act.querySelectorAll("[data-do]")) b.onclick = () => run(p, b.dataset.do, b);
  col.querySelector(".forget").classList.toggle("hide", !p.identity);
  col.querySelector(".explorer").classList.toggle("hide", !held);
  renderList(p);
  renderSteps(p);
}

function renderList(p) {
  const col = $(`col-${p.name}`);
  const list = col.querySelector(".records");
  const all = [...p.records.values()].sort((a, b) => b.version - a.version);
  const q = p.query.toLowerCase();
  const shown = all.filter((r) => {
    if (p.filter === "mine" && r.author !== p.name) return false;
    if (p.filter === "others" && (r.author === p.name || r.status !== "active")) return false;
    if (p.filter === "retracted" && r.status === "active") return false;
    return !q || `${r.title} ${r.text} ${r.key}`.toLowerCase().includes(q);
  });
  col.querySelector(".count").textContent = `${all.length} record${all.length === 1 ? "" : "s"}`;
  for (const f of col.querySelectorAll("[data-filter]")) f.classList.toggle("on", f.dataset.filter === p.filter);
  if (!shown.length) {
    list.innerHTML = `<li class="empty">${all.length ? "Nothing matches." : "Nothing in this room yet."}</li>`;
    return;
  }
  list.innerHTML = shown.map((r) => {
    const mine = r.author === p.name;
    const by = r.author ? `<span class="by by-${esc(r.author)}">${esc(mine ? "you" : cap(r.author))}</span>` : `<span class="by">unknown</span>`;
    const body = r.status !== "active"
      ? `<em class="muted">retracted — the body is gone; the key and version remain</em>`
      : r.error
        ? `<em class="bad">could not open: ${esc(r.error)}</em>`
        : esc(r.text);
    return `<li class="rec ${p.fresh.has(r.key) ? "new" : ""} ${r.status !== "active" ? "gone" : ""}">
      <details data-key="${esc(r.key)}" ${p.expanded.has(r.key) ? "open" : ""}>
        <summary>
          <span class="rec-title">${esc(r.title)}</span> ${by}
          <span class="rec-meta">v${r.version} · epoch ${r.epoch ?? "–"}${r.at ? " · " + ago(r.at) : ""}</span>
          <span class="rec-snip">${r.status === "active" && !r.error ? esc(r.text.slice(0, 90)) : ""}</span>
        </summary>
        <div class="rec-body">${body}</div>
        <dl class="rec-facts">
          <dt>key</dt><dd class="mono">${esc(r.key)}</dd>
          <dt>sealed under</dt><dd>epoch ${r.epoch ?? "–"} · ${r.bytes} bytes</dd>
          ${r.ciphertext ? `<dt>what the host holds</dt><dd class="mono cipher">${esc(r.ciphertext.slice(0, 220))}…</dd>` : ""}
        </dl>
        ${r.status === "active" ? `<button class="ghost small" data-retract="${esc(r.key)}">Retract (needs <code>curate</code>)</button>` : ""}
      </details></li>`;
  }).join("");
  for (const d of list.querySelectorAll("details[data-key]")) {
    d.ontoggle = () => { d.open ? p.expanded.add(d.dataset.key) : p.expanded.delete(d.dataset.key); };
  }
  for (const b of list.querySelectorAll("[data-retract]")) {
    b.onclick = () => run(p, "retract", b, b.dataset.retract);
  }
}

function renderSteps(p) {
  const el = $(`col-${p.name}`).querySelector(".steps");
  el.innerHTML = p.steps.map((s) => `<li>${esc(s)}</li>`).join("");
  el.closest("details").classList.toggle("hide", !p.steps.length);
}

function renderHost() {
  const rows = [...hostRows.values()].sort((a, b) => b.version - a.version);
  $("host-count").textContent = `${rows.length} record${rows.length === 1 ? "" : "s"} · 0 keys`;
  $("host-rows").innerHTML = rows.length
    ? rows.map((r) => `<li class="hrow ${r.status !== "active" ? "gone" : ""}">
        <div class="hrow-top"><span class="lock">🔒</span><span class="mono">${esc(r.key)}</span></div>
        <div class="hrow-meta">v${r.version} · epoch ${r.epoch ?? "–"} · ${r.status === "active" ? `${r.bytes} bytes` : "tombstone"}</div>
        ${r.status === "active" ? `<div class="mono cipher">${esc(r.ciphertext.slice(0, 64))}…</div>` : ""}
      </li>`).join("")
    : `<li class="empty">Nothing stored yet.</li>`;
}

function renderNext() {
  const [a, b] = people;
  const room = roomInfo();
  const totalBy = (who) => [...a.records.values(), ...b.records.values()].filter((r) => r.author === who).length;
  const next =
    !room ? "Pick a room."
    : !a.identity ? "Step 1 — create Alice's key."
    : !a.held() ? `Step 2 — Alice asks to join ${room.label}.`
    : !totalBy("alice") ? "Step 3 — Alice writes something. It is sealed in her browser before it leaves."
    : !b.identity ? "Step 4 — create Bob's key. Note that Bob cannot see anything yet."
    : !b.held() ? "Step 5 — Bob asks to join. He'll be able to open Alice's earlier notes via the epoch key chain."
    : !totalBy("bob") ? "Step 6 — Bob writes back. Watch it appear in Alice's column."
    : !room.grants.includes("curate") ? "Step 7 — try Retract in this room: it has no curate grant, so the browser refuses before sending. Then try it in The Workshop."
    : "Explore: search, filter, open a record to see what the host holds, retract with curate.";
  $("next").textContent = next;
}

function renderAll() {
  renderRooms();
  for (const p of people) renderPerson(p);
  renderHost();
  renderNext();
}

// ── actions ───────────────────────────────────────────────────────────────────
async function run(p, what, button, arg) {
  const col = $(`col-${p.name}`);
  const err = col.querySelector(".err");
  err.textContent = "";
  if (button) { button.disabled = true; button.dataset.label ??= button.innerHTML; button.innerHTML = "Working…"; }
  try {
    if (what === "mint") p.mint();
    if (what === "join") { await p.join(); await p.refresh({ announce: false }); }
    if (what === "write") {
      const title = col.querySelector(".c-title").value.trim();
      const text = col.querySelector(".c-text").value;
      if (!title) throw new Error("give it a title");
      await p.write(title, text);
      col.querySelector(".c-title").value = ""; col.querySelector(".c-text").value = "";
    }
    if (what === "retract") await p.retract(arg);
  } catch (e) {
    err.textContent = e.message ?? String(e);
    console.error(`[${p.name}]`, e);
  } finally {
    if (button?.isConnected) { button.disabled = false; button.innerHTML = button.dataset.label; }
    renderAll();
  }
}

async function selectRoom(did) {
  roomDid = did;
  S.set("dr2:room", did);
  hostRows.clear();
  for (const p of people) { p.records = new Map(); p.steps = []; p.member = null; }
  renderAll();
  for (const p of people) {
    if (!p.identity || !p.held()) continue;
    try { await p.open(); await p.refresh({ announce: false }); } catch (e) { console.error(e); }
  }
  renderAll();
}

async function poll() {
  for (const p of people) {
    if (p.busy || !p.member) continue;
    p.busy = true;
    try { await p.refresh(); } catch (e) { console.warn(`[${p.name}] refresh`, e); }
    p.busy = false;
  }
  renderAll();
  setTimeout(poll, POLL_MS);
}

// ── wiring ────────────────────────────────────────────────────────────────────
for (const p of people) {
  const col = $(`col-${p.name}`);
  col.querySelector(".forget").onclick = () => {
    if (!confirm(`Destroy ${p.label}'s key and every room key it holds? There is no recovery.`)) return;
    p.forget(); renderAll();
  };
  col.querySelector(".search").oninput = (e) => { p.query = e.target.value; renderList(p); };
  for (const f of col.querySelectorAll("[data-filter]")) f.onclick = () => { p.filter = f.dataset.filter; renderList(p); };
}

catalogue = await (await fetch("/api/rooms")).json();
if (!roomInfo()) roomDid = catalogue[0]?.roomDid ?? null;
renderTimeline();
await selectRoom(roomDid);
setTimeout(poll, POLL_MS);
