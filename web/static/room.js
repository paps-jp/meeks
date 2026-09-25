// Meeks room client.
//
// Room key: the URL carries no key. The person who opens a room that does
// not exist yet creates the key. Anyone else submits a join request; when a
// member approves it, the key is encrypted to the applicant's public key and
// delivered (via the server, which stores it while the applicant is offline
// but cannot decrypt it). Everyone keeps the key in localStorage, so
// reopening the URL works without asking again.
//
// Transport per peer, best first:
//   1. WebRTC DataChannel, direct P2P (found via STUN)
//   2. WebRTC DataChannel relayed by the TURN server (still DTLS end to end)
//   3. WebSocket relay through the signaling server
// Every application payload is additionally sealed with the room key, so it
// is end-to-end encrypted whichever transport carries it.

import { t, pickLang, loadLang, applyI18n, rememberLang, LANGS } from "./i18n.js";
import { importRoomKey, newRawKey, newECDH, newInboxKey, importInboxKey, sharedKey, confirmCode, seal, open, b64u, fromB64u, randomId } from "./crypto.js";

const $ = (id) => document.getElementById(id);

const CHUNK = 60 * 1024;                 // file chunk size (fits DataChannel and relay limits)
const MAX_FILE = 100 * 1024 * 1024;      // per-file send limit
const HISTORY_FILE_MAX = 20 * 1024 * 1024; // files larger than this are not re-shared as history
const HISTORY_LIMIT = 1000;              // messages compared per history sync
const HISTORY_BATCH_BYTES = 40 * 1024;
const SYNC_TIMEOUT_MS = 30000;
const HELLO_FALLBACK_MS = 4000;          // greet over the relay if P2P is not up by then
const INLINE_IMAGE = /^image\/(png|jpeg|gif|webp|avif|bmp)$/;

const roomId = decodeURIComponent(location.pathname.slice(1)); // rooms live at /{room}
// Diagnostics: ?transport=turn forces TURN relaying, ?transport=relay forces
// the WebSocket relay for chat and files.
const forcedTransport = new URLSearchParams(location.search).get("transport");

let rk = null;           // room key: { key, fingerprint, keyId, raw, inbox, inboxPriv }
let myId = "";           // signaling ID, changes on every connection
let ws = null;
let iceServers = [];
let localStream = null;
let callKind = null;     // "audio" | "video" while we are in a call
let screenStream = null; // our screen share, independent of the call
const canShare = !!navigator.mediaDevices?.getDisplayMedia; // unavailable on most phones
let closedForGood = false;
let claimed = false;     // server knows we hold the key (this connection)
let creating = false;    // we made a new key and are registering the room
let joinRequests = [];   // pending requests shown to members
const peers = new Map();   // signaling ID -> Peer (only peers sharing our key)
const roomPeers = new Set(); // every signaling ID in the room, key or not
const announced = new Set(); // peers we told our key ID
const incoming = new Map(); // file ID -> { meta, parts, got }

// ---------- small helpers ----------

function store(k, v) {
  try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch { return null; }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const selfId = store("meeks.self") || (() => { const id = randomId(9); store("meeks.self", id); return id; })();
let myName = store("meeks.name") || "";

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else if (k in e) e[k] = v;
    else e.setAttribute(k, v);
  }
  for (const c of children) if (c != null) e.append(c);
  return e;
}

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function fmtTime(ts) {
  const d = new Date(ts);
  const now = new Date();
  const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return d.toDateString() === now.toDateString() ? t : `${d.toLocaleDateString()} ${t}`;
}

// Serializes async work so encrypted messages keep their order.
function queue() {
  let chain = Promise.resolve();
  return (fn) => (chain = chain.then(fn).catch((e) => console.error(e)));
}
const inQueue = queue();
const sigQueue = queue();
const syncQueue = queue();

// ---------- local storage (IndexedDB) ----------

const db = await new Promise((resolve, reject) => {
  const r = indexedDB.open("meeks", 2);
  r.onupgradeneeded = () => {
    const d = r.result;
    if (!d.objectStoreNames.contains("messages")) {
      d.createObjectStore("messages", { keyPath: "key" }).createIndex("room", "room");
    }
    if (!d.objectStoreNames.contains("keys")) d.createObjectStore("keys");
  };
  r.onsuccess = () => resolve(r.result);
  r.onerror = () => reject(r.error);
});

function tx(storeName, mode, fn) {
  return new Promise((resolve, reject) => {
    const t = db.transaction(storeName, mode);
    const req = fn(t.objectStore(storeName));
    t.oncomplete = () => resolve(req && req.result);
    t.onerror = () => reject(t.error);
  });
}
const dbPut = (rec) => tx("messages", "readwrite", (s) => s.put({ ...rec, key: `${roomId}/${rec.id}`, room: roomId }));
const dbGet = (id) => tx("messages", "readonly", (s) => s.get(`${roomId}/${id}`));
const dbAll = async () => (await tx("messages", "readonly", (s) => s.index("room").getAll(roomId))).sort((a, b) => a.ts - b.ts);
const dbClear = async () => {
  const keys = await tx("messages", "readonly", (s) => s.index("room").getAllKeys(roomId));
  await tx("messages", "readwrite", (s) => { for (const k of keys) s.delete(k); });
};

/**
 * This browser's long-term ECDH key pair, used to receive room keys. The
 * private key is non-extractable and never leaves IndexedDB; it must persist
 * because an approval may arrive after the page was closed.
 */
async function identity() {
  let id = await tx("keys", "readonly", (s) => s.get("identity"));
  if (!id) {
    const { priv, pub } = await newECDH();
    id = { priv, pub };
    await tx("keys", "readwrite", (s) => s.put(id, "identity"));
  }
  return id;
}

// ---------- room key and join approval ----------
//
// Before approval an applicant chats with the members through the join
// request: messages are encrypted with ECDH(applicant identity key, room
// inbox key). Members hold the inbox private key alongside the room key and
// hand both to whomever they approve. Pre-approval messages are stored as
// ordinary history records (marked via: "join"), so they stay in the
// timeline after approval and spread through the normal history sync.

const keyStoreName = `meeks.key.${roomId}`;
const JOIN_TEXT_MAX = 1000;

let applicant = null;          // { id, shared } while we wait for approval
const requestCards = new Map(); // request ID -> { li, req, shared }
let roomInboxPub = "";          // the room's inbox public key as registered on the server
let pendingReqId = "";          // our join request while we wait
let inboxClaimed = false;       // we already tried to register an inbox key
const inboxOk = () => !!rk?.inbox && rk.inbox.pub === roomInboxPub;

/**
 * Adopts (or creates) the room's inbox key. Rooms created before inbox keys
 * existed get one from the first member who connects; the others receive it
 * in the (room-key encrypted) hello.
 */
async function setInbox(inbox) {
  rk.inbox = inbox;
  rk.inboxPriv = await importInboxKey(inbox.jwk);
  store(keyStoreName, JSON.stringify({ k: b64u(rk.raw), inbox }));
  for (const c of requestCards.values()) c.li.remove(); // redrawn with reply boxes
  requestCards.clear();
}

async function useKey(raw, inbox) {
  rk = { ...(await importRoomKey(raw)), raw, inbox: inbox || null };
  rk.inboxPriv = inbox?.jwk ? await importInboxKey(inbox.jwk) : null;
  store(keyStoreName, JSON.stringify({ k: b64u(raw), inbox: rk.inbox }));
  $("fingerprint").textContent = rk.fingerprint;
  applicant = null;
  $("join-banner").hidden = true;
  setComposerMode("member");
  renderMembers();
}

function forgetKey() {
  rk = null;
  try { localStorage.removeItem(keyStoreName); } catch { /* storage unavailable */ }
  $("fingerprint").textContent = "";
  setComposerMode("off");
}

async function loadStoredKey() {
  try {
    const s = JSON.parse(store(keyStoreName) || "null");
    if (s?.k) await useKey(fromB64u(s.k), s.inbox);
  } catch {
    console.warn("ignoring a corrupt stored key");
  }
}

/** Creates the room key and inbox key pair for a room nobody has opened yet. */
async function createRoom() {
  await useKey(newRawKey(), await newInboxKey());
  claim(true);
}

/** Tells the server we hold the key (and, if creating, registers the room). */
function claim(create) {
  creating = create;
  wsSend({ type: "claim", data: { create, inboxPub: rk.inbox?.pub || "" } });
}

async function onClaimResult(m) {
  if (!m.ok) {
    // Someone registered this room a moment before us: ask to join instead.
    creating = false;
    forgetKey();
    notice(t("room.notice.nameTaken"));
    await requestJoin();
    return;
  }
  if (creating) notice(t("room.notice.created"));
  creating = false;
  claimed = true;
  for (const id of roomPeers) announce(id);
  roomInboxPub = m.inboxPub || "";
  if (!roomInboxPub && !inboxClaimed) {
    inboxClaimed = true;
    if (!rk.inbox) await setInbox(await newInboxKey());
    claim(false); // registers the inbox key; the next result draws the cards
    return;
  }
  await renderRequests(m.requests);
}

/** Lets a peer know our key ID; peers with the same ID connect. */
function announce(id) {
  if (!rk || !claimed || announced.has(id)) return;
  announced.add(id);
  wsSend({ type: "kx", to: id, data: { keyId: rk.keyId } });
}

function onKx(from, d) {
  if (!rk || d?.keyId !== rk.keyId) return;
  announce(from);
  ensurePeer(from);
}

// --- applicant side ---

async function requestJoin() {
  const me = await identity();
  $("join-code").textContent = await confirmCode(me.pub);
  showJoinBanner("pending");
  wsSend({ type: "join-request", data: { name: myName, pub: b64u(me.pub) } });
}

async function onJoinStatus(m) {
  if (rk) return;
  if (m.error) return showJoinBanner("error");
  const req = m.request;
  if (req.status === "rejected") {
    applicant = null;
    setComposerMode("off");
    return showJoinBanner("rejected");
  }
  if (req.status === "pending") {
    const me = await identity();
    pendingReqId = req.id;
    await enableApplicantChat(m.inboxPub);
    if (applicant) {
      for (const msg of req.messages || []) await acceptJoinMessage(applicant.shared, msg);
    }
    setComposerMode(applicant ? "applicant" : "off");
    return showJoinBanner("pending");
  }
  if (req.status !== "approved") return;
  const me = await identity();
  const shared = await sharedKey(me.priv, fromB64u(req.approverPub));
  let header;
  try {
    ({ header } = await open(shared, fromB64u(req.wrap)));
  } catch {
    return showJoinBanner("error");
  }
  await useKey(fromB64u(header.k), header.inbox);
  wsSend({ type: "join-done", data: { id: req.id } });
  notice(t("room.notice.approvedBy", { name: String(header.by || t("room.participant")).slice(0, 32) }));
  claim(false);
}

/** Lets a waiting applicant write to the members once the room has an inbox key. */
async function enableApplicantChat(inboxPub) {
  if (applicant || !inboxPub || !pendingReqId || rk) return;
  const me = await identity();
  applicant = { id: pendingReqId, shared: await sharedKey(me.priv, fromB64u(inboxPub)) };
  setComposerMode("applicant");
  showJoinBanner("pending");
}

function showJoinBanner(state) {
  const text = {
    pending: applicant
      ? t("room.join.pendingChat")
      : t("room.join.pending"),
    rejected: t("room.join.rejected"),
    error: t("room.join.error"),
  }[state];
  $("join-text").textContent = text;
  $("join-code-line").hidden = state !== "pending";
  $("join-banner").hidden = false;
}

// --- messages on a join request (both sides) ---

async function sendJoinMessage(reqId, shared, text) {
  const rec = {
    id: randomId(), from: selfId, name: myName, ts: Date.now(),
    type: "text", text: text.slice(0, JOIN_TEXT_MAX), via: "join", reads: {},
  };
  await dbPut(rec);
  renderMessage(rec);
  const data = b64u(await seal(shared, { t: "join-msg", ...rec }));
  wsSend({ type: "join-message", data: { id: reqId, msgId: rec.id, data } });
}

async function acceptJoinMessage(shared, msg) {
  try {
    const { header } = await open(shared, fromB64u(msg.data));
    if (header.t === "join-msg") await acceptRecord({ ...header, via: "join" });
  } catch {
    console.warn("dropped a join message that failed to decrypt");
  }
}

async function onJoinMessage(m) {
  if (applicant && m.id === applicant.id) {
    await acceptJoinMessage(applicant.shared, m.message);
    return;
  }
  const card = requestCards.get(m.id);
  if (card?.shared) await acceptJoinMessage(card.shared, m.message);
}

// --- member side ---

/** Shows each pending request in the bar above the timeline. */
async function renderRequests(list) {
  joinRequests = rk && claimed ? (list || []) : [];
  const live = new Set(joinRequests.map((r) => r.id));
  for (const [id, card] of requestCards) {
    if (!live.has(id)) {
      card.li.remove();
      requestCards.delete(id);
    }
  }
  for (const req of joinRequests) {
    let card = requestCards.get(req.id);
    if (!card) {
      const shared = inboxOk() ? await sharedKey(rk.inboxPriv, fromB64u(req.pub)) : null;
      card = { req, shared, li: await requestCard(req, shared) };
      requestCards.set(req.id, card);
    }
    if (card.shared) {
      for (const msg of req.messages || []) await acceptJoinMessage(card.shared, msg);
    }
  }
  $("requests").hidden = !requestCards.size;
  updateTitle();
}

async function requestCard(req, shared) {
  const code = await confirmCode(fromB64u(req.pub));
  const approve = el("button", { class: "primary", textContent: t("room.req.approve") });
  const reject = el("button", { textContent: t("room.req.reject") });
  const input = el("input", { placeholder: t("room.req.replyTo", { name: req.name }), maxLength: JOIN_TEXT_MAX });
  const reply = el("form", { class: "row request-reply" }, input, el("button", { textContent: t("room.send") }));
  approve.onclick = () => { approve.disabled = reject.disabled = true; approveRequest(req); };
  reject.onclick = () => {
    if (!confirm(t("room.req.rejectConfirm", { name: req.name }))) return;
    approve.disabled = reject.disabled = true;
    wsSend({ type: "join-reject", data: { id: req.id } });
  };
  reply.onsubmit = (e) => {
    e.preventDefault();
    const v = input.value.trim();
    if (!v || !shared) return;
    input.value = "";
    sendJoinMessage(req.id, shared, v);
  };
  const li = el("div", { class: "request-card" },
    el("div", { class: "request-head" },
      el("span", { textContent: t("room.req.title", { name: req.name }) }),
      el("span", { class: "hint" }, t("room.req.code") + " ", el("code", { textContent: code, dir: "ltr" }))),
    el("div", { class: "row request-actions" }, approve, reject),
    shared ? reply : el("p", { class: "hint", textContent: t("room.req.noReply") }));
  $("requests").append(li);
  return li;
}

async function approveRequest(req) {
  const eph = await newECDH();
  const shared = await sharedKey(eph.priv, fromB64u(req.pub));
  const wrap = await seal(shared, { k: b64u(rk.raw), inbox: inboxOk() ? rk.inbox : null, by: myName });
  wsSend({ type: "join-approve", data: { id: req.id, pub: b64u(eph.pub), wrap: b64u(wrap) } });
}

// ---------- read receipts ----------

const unread = new Set();        // IDs of others' messages we have not read
const onScreen = new Set();      // unread IDs currently visible in the list
let pendingReads = [];
let readTimer = 0;

const readObserver = new IntersectionObserver((entries) => {
  for (const e of entries) {
    const id = e.target.dataset.id;
    if (e.isIntersecting) onScreen.add(id);
    else onScreen.delete(id);
  }
  flushReads();
}, { root: $("messages"), threshold: 0.5 });

function isUnreadForMe(rec) {
  return rec.from !== selfId && !rec.reads?.[selfId];
}

/** Marks visible messages as read while the window is in front. */
function flushReads() {
  if (document.visibilityState !== "visible" || !document.hasFocus()) return;
  for (const id of onScreen) markRead(id);
}

async function markRead(id) {
  if (!unread.delete(id)) return;
  onScreen.delete(id);
  const li = rendered.get(id);
  if (li) readObserver.unobserve(li);
  updateTitle();
  const rec = await dbGet(id);
  if (!rec) return;
  rec.reads = { ...rec.reads, [selfId]: myName };
  await dbPut(rec);
  pendingReads.push(id);
  clearTimeout(readTimer);
  readTimer = setTimeout(() => {
    const ids = pendingReads;
    pendingReads = [];
    // applicants have no room key yet; their receipts travel with the next sync
    if (ids.length && rk) broadcast({ t: "read", by: selfId, name: myName, ids });
  }, 300);
}

/** Adds readers to a stored message; returns true if anything changed. */
async function mergeReads(id, reads) {
  const rec = await dbGet(id);
  if (!rec) return false;
  let changed = false;
  const merged = { ...rec.reads };
  for (const [who, name] of Object.entries(cleanReads(reads))) {
    if (who === rec.from || merged[who]) continue;
    merged[who] = name;
    changed = true;
  }
  if (!changed) return false;
  rec.reads = merged;
  await dbPut(rec);
  updateReceipt(rec);
  return true;
}

function receiptText(rec) {
  const names = Object.entries(rec.reads || {}).filter(([k]) => k !== selfId).map(([, n]) => n);
  return { text: names.length ? t("room.read", { n: names.length }) : "", title: names.join(t("room.listSep")) };
}

function updateReceipt(rec) {
  const span = rendered.get(rec.id)?.querySelector(".receipt");
  if (!span) return;
  const r = receiptText(rec);
  span.textContent = r.text;
  span.title = r.title;
}

function updateTitle() {
  const prefix = (joinRequests.length ? t("room.titleRequests") : "") + (unread.size ? `(${unread.size}) ` : "");
  document.title = `${prefix}${roomId} - Meeks`;
}

// ---------- message rendering ----------

const rendered = new Map(); // message id -> <li>
const objectUrls = new Map(); // message id -> [urls]

function renderMessage(rec, progress) {
  for (const u of objectUrls.get(rec.id) || []) URL.revokeObjectURL(u);
  objectUrls.delete(rec.id);
  const mine = rec.from === selfId;
  const li = el("li", { class: "msg" + (mine ? " mine" : "") });
  li.dataset.ts = rec.ts;
  li.dataset.id = rec.id;
  const meta = el("div", { class: "meta" },
    el("span", { class: "name", textContent: rec.name || "?" }),
    el("time", { textContent: fmtTime(rec.ts) }),
    rec.via === "join" ? el("span", { class: "tag", textContent: t("room.tag.join") }) : null);
  if (mine) {
    const r = receiptText(rec);
    meta.prepend(el("span", { class: "receipt", textContent: r.text, title: r.title }));
  }
  li.append(meta);

  if (rec.type === "text") {
    li.append(el("div", { class: "body", textContent: rec.text }));
  } else {
    li.append(renderFile(rec, progress));
  }

  const old = rendered.get(rec.id);
  rendered.set(rec.id, li);
  const list = $("messages");
  const atBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 40;
  if (old) {
    readObserver.unobserve(old);
    onScreen.delete(rec.id);
    old.replaceWith(li);
  } else {
    // keep chronological order when history arrives out of order
    let next = null;
    for (let n = list.lastElementChild; n && Number(n.dataset.ts) > rec.ts; n = n.previousElementSibling) next = n;
    if (isUnreadForMe(rec) && !unread.size && !pageActive()) placeDivider(next);
    list.insertBefore(li, next);
  }
  if (isUnreadForMe(rec)) {
    unread.add(rec.id);
    readObserver.observe(li);
  }
  updateTitle();
  if (atBottom || mine) list.scrollTop = list.scrollHeight;
}

const pageActive = () => document.visibilityState === "visible" && document.hasFocus();

/** Moves the "unread from here" divider in front of `before` (null = end). */
function placeDivider(before) {
  document.querySelector(".unread-divider")?.remove();
  const d = el("li", { class: "unread-divider", textContent: t("room.unreadDivider") });
  d.dataset.ts = before?.dataset.ts ?? Date.now();
  $("messages").insertBefore(d, before);
}

function renderFile(rec, progress) {
  const f = rec.file;
  const box = el("div", { class: "body file" });
  if (!rec.blob) {
    const label = progress != null ? t("room.file.receiving", { p: Math.floor(progress * 100) }) : t("room.file.missing");
    box.append(el("div", { class: "file-name", textContent: `📄 ${f.name} (${fmtSize(f.size)})` }),
      el("div", { class: "hint", textContent: label }));
    return box;
  }
  const urls = [];
  // Previews use a type from a fixed allowlist; downloads are always
  // octet-stream so a received file can never render as a page on our origin.
  if (INLINE_IMAGE.test(f.mime)) {
    const u = URL.createObjectURL(new Blob([rec.blob], { type: f.mime }));
    urls.push(u);
    box.append(el("img", { src: u, alt: f.name, class: "preview" }));
  } else if (/^video\/(mp4|webm|ogg)$/.test(f.mime)) {
    const u = URL.createObjectURL(new Blob([rec.blob], { type: f.mime }));
    urls.push(u);
    box.append(el("video", { src: u, controls: true, class: "preview" }));
  } else if (/^audio\/(mpeg|ogg|wav|webm|mp4|aac)$/.test(f.mime)) {
    const u = URL.createObjectURL(new Blob([rec.blob], { type: f.mime }));
    urls.push(u);
    box.append(el("audio", { src: u, controls: true }));
  }
  const dl = URL.createObjectURL(new Blob([rec.blob], { type: "application/octet-stream" }));
  urls.push(dl);
  box.append(el("a", { href: dl, download: f.name, class: "file-name", textContent: `⬇ ${f.name} (${fmtSize(f.size)})` }));
  objectUrls.set(rec.id, urls);
  return box;
}

function notice(text) {
  const li = el("li", { class: "notice", textContent: text });
  li.dataset.ts = Date.now();
  $("messages").append(li);
  $("messages").scrollTop = $("messages").scrollHeight;
}

// ---------- peers ----------

class Peer {
  constructor(id) {
    this.id = id;
    this.name = "…";
    this.inCall = false;
    this.route = "connecting"; // connecting | p2p | turn | relay
    this.polite = myId < id;
    this.makingOffer = false;
    this.ignoreOffer = false;
    this.greeted = false;
    this.senders = { cam: [], screen: [] };
    this.streams = new Map(); // remote stream ID -> MediaStream
    this.screenId = null;     // ID of the remote stream that is a screen share
    this.sharing = false;
    this.syncDone = null;

    this.pc = new RTCPeerConnection({
      iceServers,
      iceTransportPolicy: forcedTransport === "turn" ? "relay" : "all",
    });
    // Negotiated channel: both sides create it, no in-band handshake needed.
    this.dc = this.pc.createDataChannel("meeks", { negotiated: true, id: 0 });
    this.dc.binaryType = "arraybuffer";
    this.dc.onopen = () => { this.hello(); this.updateRoute(); };
    this.dc.onclose = () => this.updateRoute();
    this.dc.onmessage = (e) => inQueue(() => receive(this, new Uint8Array(e.data)));

    this.pc.onnegotiationneeded = async () => {
      try {
        this.makingOffer = true;
        await this.pc.setLocalDescription();
        sendSignal(this.id, { description: this.pc.localDescription });
      } catch (e) {
        console.error(e);
      } finally {
        this.makingOffer = false;
      }
    };
    this.pc.onicecandidate = ({ candidate }) => { if (candidate) sendSignal(this.id, { candidate }); };
    this.pc.onconnectionstatechange = () => {
      if (this.pc.connectionState === "failed") this.pc.restartIce();
      this.updateRoute();
    };
    this.pc.ontrack = ({ track, streams }) => {
      const stream = streams[0] || new MediaStream([track]);
      this.streams.set(stream.id, stream);
      this.showStream(stream);
      stream.onremovetrack = () => {
        if (stream.getTracks().length) return;
        this.streams.delete(stream.id);
        removeStreamTile(stream); // by stream, not key: the screen ID may already be cleared
      };
    };

    if (localStream) this.addStream(localStream);
    if (screenStream) this.addStream(screenStream, "screen");
    this.helloTimer = setTimeout(() => this.hello(), HELLO_FALLBACK_MS);
  }

  async handleSignal({ description, candidate }) {
    if (description) {
      const collision = description.type === "offer" &&
        (this.makingOffer || this.pc.signalingState !== "stable");
      this.ignoreOffer = !this.polite && collision;
      if (this.ignoreOffer) return;
      await this.pc.setRemoteDescription(description);
      if (description.type === "offer") {
        await this.pc.setLocalDescription();
        sendSignal(this.id, { description: this.pc.localDescription });
      }
    } else if (candidate) {
      try {
        await this.pc.addIceCandidate(candidate);
      } catch (e) {
        if (!this.ignoreOffer) console.warn(e);
      }
    }
  }

  get p2p() { return forcedTransport !== "relay" && this.dc.readyState === "open"; }

  /** Sends an already sealed payload over the best available transport. */
  async send(bytes) {
    if (this.p2p) {
      if (this.dc.bufferedAmount > 4 * 1024 * 1024) {
        this.dc.bufferedAmountLowThreshold = 1024 * 1024;
        await new Promise((r) => this.dc.addEventListener("bufferedamountlow", r, { once: true }));
      }
      this.dc.send(bytes);
    } else {
      await relay(this.id, bytes);
    }
  }

  async hello() {
    if (this.greeted) return;
    this.greeted = true;
    clearTimeout(this.helloTimer);
    this.send(await seal(rk.key, {
      t: "hello", name: myName, call: localStream ? callKind : false, inbox: inboxOk() ? rk.inbox : null,
      screen: screenStream ? screenStream.id : null,
    }));
  }

  /** kind is "cam" (the call) or "screen" (screen share). */
  addStream(stream, kind = "cam") {
    for (const track of stream.getTracks()) this.senders[kind].push(this.pc.addTrack(track, stream));
  }

  removeStream(kind = "cam") {
    for (const s of this.senders[kind]) {
      try { this.pc.removeTrack(s); } catch { /* connection already closed */ }
    }
    this.senders[kind] = [];
  }

  tileKey(stream) {
    return stream.id === this.screenId ? `${this.id}:screen` : this.id;
  }

  showStream(stream) {
    const screen = stream.id === this.screenId;
    showTile(this.tileKey(stream), stream, screen ? t("room.screenOf", { name: this.name }) : this.name, false, screen);
  }

  /** Redraws tiles after a rename or after learning which stream is the screen. */
  refreshTiles() {
    // A screen stream that arrived before its announcement sits in the camera tile.
    const camTile = document.querySelector(`.tile[data-id="${CSS.escape(this.id)}"] video`);
    if (camTile && camTile.srcObject?.id === this.screenId) removeTile(this.id);
    for (const stream of this.streams.values()) this.showStream(stream);
  }

  setScreen(id) {
    const old = this.screenId;
    this.screenId = id || null;
    this.sharing = !!id;
    if (old && old !== id) {
      // The ended share may still have tracks until renegotiation; forget it
      // so refreshTiles does not redraw it in the camera tile.
      this.streams.delete(old);
      removeTile(`${this.id}:screen`);
    }
    this.refreshTiles();
  }

  async updateRoute() {
    let route = "relay";
    if (this.p2p) {
      route = "p2p";
      try {
        const stats = await this.pc.getStats();
        let pair;
        stats.forEach((r) => {
          if (r.type === "transport" && r.selectedCandidatePairId) pair = stats.get(r.selectedCandidatePairId);
        });
        if (!pair) stats.forEach((r) => { if (r.type === "candidate-pair" && r.nominated && r.state === "succeeded") pair = r; });
        if (pair) {
          const l = stats.get(pair.localCandidateId), rm = stats.get(pair.remoteCandidateId);
          if (l?.candidateType === "relay" || rm?.candidateType === "relay") route = "turn";
        }
      } catch { /* stats unavailable */ }
    } else if (this.pc.connectionState === "new" || this.pc.connectionState === "connecting") {
      route = this.greeted ? "relay" : "connecting";
    }
    if (route !== this.route) {
      this.route = route;
      renderMembers();
    }
  }

  close() {
    clearTimeout(this.helloTimer);
    this.syncDone?.();
    this.pc.close();
    removeTile(this.id);
    removeTile(`${this.id}:screen`);
  }
}

/** Returns the Peer for id, creating it once both sides share the room key. */
function ensurePeer(id) {
  let p = peers.get(id);
  if (!p && rk) {
    p = new Peer(id);
    peers.set(id, p);
    renderMembers();
  }
  return p;
}

function dropPeer(id) {
  const p = peers.get(id);
  if (!p) return;
  p.close();
  peers.delete(id);
  if (p.greeted && p.name !== "…") notice(t("room.notice.left", { name: p.name }));
  renderMembers();
}

async function broadcast(header, body) {
  const bytes = await seal(rk.key, header, body);
  await Promise.all([...peers.values()].map((p) => p.send(bytes).catch(console.error)));
}

function renderMembers() {
  const ul = $("members");
  ul.replaceChildren(el("li", {}, el("span", { textContent: t("room.me", { name: myName }) }),
    callIcon(localStream && callKind), screenStream ? " 🖥️" : null));
  for (const p of peers.values()) {
    const cls = p.route === "p2p" ? "ok" : p.route === "turn" ? "mid" : "relay";
    ul.append(el("li", {},
      el("span", { textContent: p.name }),
      callIcon(p.inCall),
      p.sharing ? " 🖥️" : null,
      el("span", { class: `route ${cls}`, textContent: t(`room.route.${p.route}`) })));
  }
  const n = peers.size + 1;
  $("status").textContent = ws?.readyState !== WebSocket.OPEN ? t("room.status.reconnecting")
    : !rk ? t("room.status.waiting") : t("room.status.connected", { n });
}

// ---------- signaling ----------

function wsSend(obj) {
  if (ws?.readyState !== WebSocket.OPEN) throw new Error("not connected");
  ws.send(JSON.stringify(obj));
}

function sendSignal(to, obj) {
  sigQueue(async () => wsSend({ type: "signal", to, data: b64u(await seal(rk.key, obj)) }));
}

async function relay(to, bytes) {
  while (ws?.readyState === WebSocket.OPEN && ws.bufferedAmount > 1024 * 1024) await sleep(20);
  wsSend({ type: "relay", to, data: b64u(bytes) });
}

let retry = 0;
function connect() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${proto}//${location.host}/ws/${encodeURIComponent(roomId)}`);
  ws.onopen = () => { retry = 0; };
  ws.onmessage = (e) => inQueue(() => onServer(JSON.parse(e.data)));
  ws.onclose = (e) => {
    for (const id of [...peers.keys()]) dropPeer(id);
    roomPeers.clear();
    announced.clear();
    claimed = false;
    renderMembers();
    if (e.code === 1008 && e.reason === "room is full") {
      closedForGood = true;
      $("status").textContent = t("room.status.full");
      showWarn(t("room.warn.full"));
    }
    if (closedForGood) return;
    retry = Math.min(retry + 1, 5);
    setTimeout(connect, 1000 * 2 ** (retry - 1));
  };
}

async function onServer(m) {
  switch (m.type) {
    case "welcome":
      myId = m.id;
      iceServers = m.iceServers || [];
      for (const id of m.peers || []) roomPeers.add(id);
      if (rk) {
        claim(false);
      } else if (!m.exists) {
        await createRoom(); // nobody has created this room yet: we do
      } else {
        await requestJoin();
      }
      renderMembers();
      break;
    case "peer-joined":
      roomPeers.add(m.id);
      announce(m.id);
      break;
    case "peer-left":
      roomPeers.delete(m.id);
      announced.delete(m.id);
      dropPeer(m.id);
      break;
    case "kx":
      onKx(m.from, m.data);
      break;
    case "claim-result":
      await onClaimResult(m);
      break;
    case "join-requests":
      if (rk) {
        if (m.inboxPub) roomInboxPub = m.inboxPub;
        await renderRequests(m.requests);
      }
      else await enableApplicantChat(m.inboxPub);
      break;
    case "join-status":
      await onJoinStatus(m);
      break;
    case "join-message":
      await onJoinMessage(m);
      break;
    case "join-message-error":
      notice(m.error === "too many messages" ? t("room.err.joinMsgLimit") : t("room.err.msgFailed"));
      break;
    case "signal": {
      if (!rk) return;
      let header;
      try {
        ({ header } = await open(rk.key, fromB64u(m.data)));
      } catch {
        return; // sender holds a different key
      }
      await ensurePeer(m.from)?.handleSignal(header);
      break;
    }
    case "relay": {
      if (!rk) return;
      const bytes = fromB64u(m.data);
      let p = peers.get(m.from);
      if (!p) {
        try {
          await open(rk.key, bytes); // only peers holding our key become Peers
        } catch {
          return;
        }
        p = ensurePeer(m.from);
      }
      await receive(p, bytes);
      p.updateRoute();
      break;
    }
  }
}

// ---------- application messages ----------

async function receive(peer, bytes) {
  let msg;
  try {
    msg = await open(rk.key, bytes);
  } catch {
    console.warn("dropped a message that failed to decrypt");
    return;
  }
  const { header: h, body } = msg;
  switch (h.t) {
    case "hello":
      peer.name = String(h.name || "?").slice(0, 32);
      peer.inCall = callKindOf(h.call);
      renderMembers();
      peer.setScreen(h.screen ? String(h.screen) : null);
      notice(t("room.notice.present", { name: peer.name }));
      peer.hello(); // reply if we have not greeted yet
      if (h.inbox?.jwk && h.inbox.pub === roomInboxPub && !inboxOk()) {
        await setInbox(h.inbox);
        claim(false); // fetch the request list again to draw reply boxes
      }
      syncQueue(() => syncWith(peer));
      break;
    case "msg":
      await acceptRecord(h);
      break;
    case "history":
      for (const r of h.msgs || []) await acceptRecord(r);
      break;
    case "history-req":
      sendHistory(peer, h).catch(console.error);
      break;
    case "history-end":
      peer.syncDone?.();
      break;
    case "read":
      for (const id of (h.ids || []).slice(0, HISTORY_LIMIT)) {
        await mergeReads(String(id), { [String(h.by)]: h.name });
      }
      break;
    case "reads":
      for (const [id, reads] of Object.entries(h.map || {}).slice(0, HISTORY_LIMIT)) await mergeReads(id, reads);
      break;
    case "file-meta":
      await onFileMeta(h);
      break;
    case "file-chunk":
      await onFileChunk(h, body);
      break;
    case "call":
      peer.inCall = h.on ? callKindOf(h.kind || true) : false;
      if (!h.on) removeTile(peer.id);
      renderMembers();
      break;
    case "screen":
      peer.setScreen(h.on ? String(h.id) : null);
      renderMembers();
      break;
  }
}

function cleanReads(r) {
  const out = {};
  if (r && typeof r === "object") {
    for (const [k, v] of Object.entries(r).slice(0, 200)) out[String(k).slice(0, 64)] = String(v ?? "?").slice(0, 32);
  }
  return out;
}

function cleanRecord(r) {
  const base = {
    id: String(r.id).slice(0, 64),
    from: String(r.from || "").slice(0, 64),
    name: String(r.name || "?").slice(0, 32),
    ts: Number(r.ts) || Date.now(),
    reads: cleanReads(r.reads),
    ...(r.via === "join" ? { via: "join" } : {}),
  };
  if (r.type === "file" && r.file) {
    return { ...base, type: "file", file: {
      name: String(r.file.name || "file").slice(0, 255),
      size: Number(r.file.size) || 0,
      mime: String(r.file.mime || "application/octet-stream").slice(0, 100),
    } };
  }
  return { ...base, type: "text", text: String(r.text ?? "").slice(0, 10000) };
}

/** Stores and shows a text or file record, or merges its read receipts. */
async function acceptRecord(raw) {
  if (!raw?.id) return;
  const rec = cleanRecord(raw);
  if (await dbGet(rec.id)) {
    await mergeReads(rec.id, rec.reads);
    return;
  }
  await dbPut(rec);
  const inc = incoming.get(rec.id);
  renderMessage(rec, inc?.meta ? inc.got / inc.meta.n : undefined);
}

// History sync: each side sends the IDs of its recent messages; the other
// side replies with whatever is missing (plus read receipts and files).
// Both peers do this on every connection, so gaps fill in both directions.

async function syncWith(peer) {
  if (!peers.has(peer.id)) return;
  const recent = (await dbAll()).slice(-HISTORY_LIMIT);
  const done = new Promise((r) => (peer.syncDone = r));
  await peer.send(await seal(rk.key, {
    t: "history-req",
    ids: recent.map((r) => r.id),
    since: recent.length >= HISTORY_LIMIT ? recent[0].ts : 0,
  }));
  await Promise.race([done, sleep(SYNC_TIMEOUT_MS)]);
  peer.syncDone = null;
}

async function sendHistory(peer, req) {
  const have = new Set((Array.isArray(req.ids) ? req.ids : []).slice(0, HISTORY_LIMIT + 1).map(String));
  const since = Number(req.since) || 0;
  const recent = (await dbAll()).slice(-HISTORY_LIMIT);
  const missing = recent.filter((r) => r.ts >= since && !have.has(r.id));

  let batch = [], size = 0;
  const flush = async (t) => {
    if (!batch.length) return;
    await peer.send(await seal(rk.key, t === "history" ? { t, msgs: batch } : { t, map: Object.fromEntries(batch) }));
    batch = []; size = 0;
  };
  for (const r of missing) {
    const item = r.type === "file"
      ? { id: r.id, from: r.from, name: r.name, ts: r.ts, type: "file", file: r.file, reads: r.reads }
      : { id: r.id, from: r.from, name: r.name, ts: r.ts, type: "text", text: r.text, reads: r.reads, via: r.via };
    batch.push(item);
    size += (item.text?.length || 0) * 3 + 300;
    if (size > HISTORY_BATCH_BYTES) await flush("history");
  }
  await flush("history");

  // Read receipts for messages the peer already has.
  for (const r of recent) {
    if (!have.has(r.id) || !r.reads || !Object.keys(r.reads).length) continue;
    batch.push([r.id, r.reads]);
    size += 300;
    if (size > HISTORY_BATCH_BYTES) await flush("reads");
  }
  await flush("reads");

  for (const r of missing) {
    if (r.type === "file" && r.blob && r.file.size <= HISTORY_FILE_MAX) await sendFile([peer], r);
  }
  await peer.send(await seal(rk.key, { t: "history-end" }));
}

// ---------- files ----------

async function sendFile(targets, rec) {
  const buf = new Uint8Array(await rec.blob.arrayBuffer());
  const n = Math.max(1, Math.ceil(buf.length / CHUNK));
  const meta = await seal(rk.key, { t: "file-meta", id: rec.id, from: rec.from, name: rec.name, ts: rec.ts, file: rec.file, reads: rec.reads, n });
  for (const p of targets) await p.send(meta);
  for (let i = 0; i < n; i++) {
    const chunk = await seal(rk.key, { t: "file-chunk", id: rec.id, i }, buf.subarray(i * CHUNK, (i + 1) * CHUNK));
    for (const p of targets) await p.send(chunk).catch(console.error);
  }
}

async function onFileMeta(h) {
  const rec = cleanRecord({ ...h, type: "file" });
  const existing = await dbGet(rec.id);
  if (existing?.blob) return;
  const n = Math.min(Number(h.n) || 1, Math.ceil(MAX_FILE / CHUNK) + 1);
  const inc = incoming.get(rec.id) || { parts: [], got: 0 };
  inc.meta = { ...(existing || rec), n };
  incoming.set(rec.id, inc);
  if (!existing) await dbPut(rec);
  renderMessage(inc.meta, inc.got / n);
  await maybeFinish(rec.id);
}

async function onFileChunk(h, body) {
  const id = String(h.id);
  let inc = incoming.get(id);
  if (!inc) {
    if ((await dbGet(id))?.blob) return; // duplicate transfer
    inc = { parts: [], got: 0 };        // chunk overtook its meta
    incoming.set(id, inc);
  }
  const i = Number(h.i);
  if (!Number.isInteger(i) || i < 0 || inc.parts[i]) return;
  if (inc.meta && i >= inc.meta.n) return;
  inc.parts[i] = body.slice();
  inc.got++;
  if (inc.meta && (inc.got % 16 === 0)) renderMessage(inc.meta, inc.got / inc.meta.n);
  await maybeFinish(id);
}

async function maybeFinish(id) {
  const inc = incoming.get(id);
  if (!inc?.meta || inc.got < inc.meta.n) return;
  incoming.delete(id);
  const { n, ...meta } = inc.meta;
  // keep read receipts that arrived while the file was downloading
  const rec = { ...meta, reads: { ...meta.reads, ...(await dbGet(id))?.reads } };
  rec.blob = new Blob(inc.parts, { type: "application/octet-stream" });
  await dbPut(rec);
  renderMessage(rec);
}

async function sendFiles(files) {
  for (const file of files) {
    if (file.size > MAX_FILE) {
      notice(t("room.file.tooLarge", { name: file.name, max: fmtSize(MAX_FILE) }));
      continue;
    }
    const rec = {
      id: randomId(), from: selfId, name: myName, ts: Date.now(), type: "file", reads: {},
      file: { name: file.name, size: file.size, mime: file.type || "application/octet-stream" },
      blob: file,
    };
    await dbPut(rec);
    renderMessage(rec);
    await sendFile([...peers.values()], rec);
  }
}

// ---------- chat ----------

async function sendText(text) {
  const rec = { id: randomId(), from: selfId, name: myName, ts: Date.now(), type: "text", text, reads: {} };
  await dbPut(rec);
  renderMessage(rec);
  await broadcast({ t: "msg", ...rec });
}

// ---------- voice / video call ----------

/** Normalizes a peer's announced call state to "audio" | "video" | false. */
function callKindOf(v) {
  if (!v) return false;
  return v === "audio" ? "audio" : "video"; // older clients sent true for video
}

function callIcon(kind) {
  return kind === "audio" ? " 🎙️" : kind ? " 📹" : null;
}

function showTile(id, stream, name, muted, screen = false) {
  let tile = document.querySelector(`.tile[data-id="${CSS.escape(id)}"]`);
  if (!tile) {
    tile = el("div", { class: "tile" },
      el("video", { autoplay: true, playsInline: true, muted }),
      el("span", { class: "avatar", "aria-hidden": "true" }),
      el("span", { class: "label" }));
    tile.dataset.id = id;
    $("video-grid").append(tile);
  }
  const v = tile.querySelector("video");
  if (v.srcObject !== stream) v.srcObject = stream;
  tile.querySelector(".label").textContent = name;
  tile.classList.toggle("screen", screen);
  tile.querySelector(".avatar").textContent = ([...String(name).trim()][0] || "?").toUpperCase();
  // Voice-only participants show an avatar; the <video> keeps playing audio.
  const update = () => tile.classList.toggle("audio-only", stream.getVideoTracks().length === 0);
  update();
  if (tile.watched !== stream) { // listen once per stream (showTile runs for every track)
    tile.watched = stream;
    stream.addEventListener("addtrack", update);
    stream.addEventListener("removetrack", update);
  }
  $("videos").hidden = false;
}

/** Removes whichever tile currently shows stream. */
function removeStreamTile(stream) {
  for (const tile of document.querySelectorAll(".tile")) {
    if (tile.querySelector("video")?.srcObject === stream) removeTile(tile.dataset.id);
  }
}

function removeTile(id) {
  document.querySelector(`.tile[data-id="${CSS.escape(id)}"]`)?.remove();
  if (!$("video-grid").children.length) $("videos").hidden = true;
}

/** Shares a screen, window or tab; works with or without a call. */
async function startShare() {
  setCallMenu(false);
  if (screenStream || !canShare) return;
  try {
    screenStream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: true });
  } catch (e) {
    if (e.name !== "NotAllowedError") notice(t("room.err.share", { msg: e.message })); // not when the user cancels
    return;
  }
  const video = screenStream.getVideoTracks()[0];
  if (video) {
    video.contentHint = "detail"; // favor sharp text over frame rate
    video.addEventListener("ended", stopShare); // the browser's own "Stop sharing" button
  }
  // Announce first so peers can label the stream as a screen when it arrives.
  await broadcast({ t: "screen", on: true, id: screenStream.id });
  showTile("self:screen", screenStream, t("room.screenOf", { name: myName }), true, true);
  for (const p of peers.values()) p.addStream(screenStream, "screen");
  updateMediaButtons();
  renderMembers();
}

function stopShare() {
  if (!screenStream) return;
  for (const p of peers.values()) p.removeStream("screen");
  for (const track of screenStream.getTracks()) track.stop();
  screenStream = null;
  removeTile("self:screen");
  broadcast({ t: "screen", on: false });
  updateMediaButtons();
  renderMembers();
}

function setCallMenu(open) {
  $("call-menu").hidden = !open;
  $("call").setAttribute("aria-expanded", String(open));
  if (open) $("call-menu").querySelector("button").focus();
}

/** Starts a call; kind is "audio" (microphone only) or "video". */
async function startCall(kind) {
  setCallMenu(false);
  if (localStream) return;
  try {
    localStream = await navigator.mediaDevices.getUserMedia(
      kind === "video" ? { audio: true, video: true } : { audio: true });
  } catch (e) {
    if (kind !== "video") {
      notice(t("room.err.media", { msg: e.message }));
      return;
    }
    try {
      localStream = await navigator.mediaDevices.getUserMedia({ audio: true }); // no camera: fall back to voice
    } catch (e2) {
      notice(t("room.err.media", { msg: e2.message }));
      return;
    }
  }
  callKind = localStream.getVideoTracks().length ? "video" : "audio";
  showTile("self", localStream, t("room.me", { name: myName }), true);
  for (const p of peers.values()) p.addStream(localStream);
  $("call-wrap").hidden = true;
  updateMediaButtons();
  renderMembers();
  broadcast({ t: "call", on: true, kind: callKind });
}

function hangup() {
  if (!localStream) return;
  for (const p of peers.values()) p.removeStream();
  for (const track of localStream.getTracks()) track.stop();
  localStream = null;
  callKind = null;
  removeTile("self");
  $("call-wrap").hidden = false;
  renderMembers();
  broadcast({ t: "call", on: false });
}

/** Ends the call, disconnects (without reconnecting) and returns home. The
 * room key stays on this device, so reopening the URL rejoins directly. */
function leaveRoom() {
  hangup();
  stopShare();
  closedForGood = true;
  ws?.close(1000, "left");
  const lang = document.documentElement.lang;
  location.href = lang === "ja" ? "/" : `/${lang}`;
}

function toggleTrack(kind) {
  const tracks = kind === "audio" ? localStream?.getAudioTracks() : localStream?.getVideoTracks();
  for (const t of tracks || []) t.enabled = !t.enabled;
  updateMediaButtons();
}

function updateMediaButtons() {
  const a = localStream?.getAudioTracks()[0], v = localStream?.getVideoTracks()[0];
  $("toggle-mic").textContent = t("room.mic", { state: t(a?.enabled ? "room.on" : "room.off") });
  $("toggle-cam").textContent = t("room.cam", { state: t(v ? (v.enabled ? "room.on" : "room.off") : "room.none") });
  $("toggle-mic").hidden = $("hangup").hidden = !localStream;
  $("toggle-cam").hidden = !v; // voice calls have no camera to toggle
  $("toggle-share").textContent = t(screenStream ? "room.stopShare" : "room.shareScreen");
  $("toggle-share").hidden = !canShare || (!localStream && !screenStream);
  $("share-item").hidden = !canShare || !!screenStream;
}

// ---------- UI ----------

function showWarn(text) {
  $("warn").textContent = text;
  $("warn").hidden = false;
}

/** "member": full chat, "applicant": text to the join request only, "off". */
function setComposerMode(mode) {
  $("text").disabled = $("send").disabled = mode === "off";
  $("file").disabled = $("call").disabled = mode !== "member";
  $("file-btn").hidden = mode !== "member";
  $("text").placeholder = {
    member: t("room.ph.member"),
    applicant: t("room.ph.applicant"),
    off: t("room.ph.off"),
  }[mode];
}

async function askName() {
  if (myName) return;
  const dlg = $("name-dialog");
  dlg.showModal();
  dlg.addEventListener("cancel", (e) => e.preventDefault());
  await new Promise((r) => dlg.addEventListener("close", r, { once: true }));
  myName = $("name-input").value.trim().slice(0, 32) || t("room.guest");
  store("meeks.name", myName);
}

function bindUI() {
  $("room-title").textContent = roomId;
  updateTitle();

  $("copy-url").onclick = async () => {
    await navigator.clipboard.writeText(location.origin + location.pathname);
    $("copy-url").textContent = t("room.copied");
    setTimeout(() => ($("copy-url").textContent = t("room.copyUrl")), 1500);
  };
  $("call").onclick = (e) => {
    e.stopPropagation();
    setCallMenu($("call-menu").hidden);
  };
  for (const item of $("call-menu").querySelectorAll("[data-kind]")) {
    item.onclick = () => (item.dataset.kind === "screen" ? startShare() : startCall(item.dataset.kind));
  }
  document.addEventListener("click", (e) => {
    if (!$("call-menu").hidden && !$("call-wrap").contains(e.target)) setCallMenu(false);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !$("call-menu").hidden) {
      setCallMenu(false);
      $("call").focus();
    }
  });
  $("hangup").onclick = hangup;
  $("toggle-share").onclick = () => (screenStream ? stopShare() : startShare());
  $("leave").onclick = leaveRoom;
  $("toggle-mic").onclick = () => toggleTrack("audio");
  $("toggle-cam").onclick = () => toggleTrack("video");

  $("clear-history").onclick = async () => {
    if (!confirm(t("room.clearConfirm"))) return;
    await dbClear();
    for (const li of rendered.values()) readObserver.unobserve(li);
    $("messages").replaceChildren();
    rendered.clear();
    unread.clear();
    onScreen.clear();
    updateTitle();
  };

  const text = $("text");
  $("composer").onsubmit = (e) => {
    e.preventDefault();
    const v = text.value.trim();
    if (!v) return;
    if (rk) {
      text.value = "";
      sendText(v);
    } else if (applicant) {
      text.value = "";
      sendJoinMessage(applicant.id, applicant.shared, v);
    }
  };
  text.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      $("composer").requestSubmit();
    }
  });
  text.addEventListener("paste", (e) => {
    const files = [...(e.clipboardData?.files || [])];
    if (files.length && rk) { e.preventDefault(); sendFiles(files); }
  });
  $("file").onchange = (e) => { if (rk) sendFiles([...e.target.files]); e.target.value = ""; };

  const chat = document.querySelector(".chat");
  chat.addEventListener("dragover", (e) => { e.preventDefault(); chat.classList.add("drop"); });
  chat.addEventListener("dragleave", () => chat.classList.remove("drop"));
  chat.addEventListener("drop", (e) => {
    e.preventDefault();
    chat.classList.remove("drop");
    if (rk) sendFiles([...e.dataTransfer.files]);
  });

  document.addEventListener("visibilitychange", flushReads);
  window.addEventListener("focus", flushReads);
  updateMediaButtons();
}

async function main() {
  const lang = pickLang();
  await loadLang(lang);
  applyI18n();
  document.querySelector(".topbar .logo").href = lang === "ja" ? "/" : `/${lang}`;
  $("safety-link").href = lang === "ja" ? "/safety" : `/${lang}/safety`;
  const select = $("lang-select");
  for (const [code, name] of LANGS) select.append(el("option", { value: code, textContent: name }));
  select.value = lang;
  select.onchange = () => {
    rememberLang(select.value);
    location.reload();
  };
  bindUI();
  setComposerMode("off");
  await loadStoredKey();
  await askName();
  const recs = await dbAll();
  const firstUnread = recs.find(isUnreadForMe);
  for (const rec of recs) renderMessage(rec);
  if (firstUnread) {
    const li = rendered.get(firstUnread.id);
    placeDivider(li);
    li.scrollIntoView({ block: "center" });
  }
  renderMembers();
  connect();
}

main();
