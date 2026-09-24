// End-to-end encryption for Meeks.
//
// Each room has a 256-bit key that never reaches the server in the clear:
// when a member approves a join request, the key is encrypted to the
// applicant's ECDH public key; everyone keeps it in localStorage. Every payload — chat, files, history and even WebRTC
// signaling — is sealed with AES-256-GCM before it leaves the browser.

const te = new TextEncoder();
const td = new TextDecoder();
const VERSION = 1;

export function b64u(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64u(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "===".slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomId(bytes = 12) {
  return b64u(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** A fresh 256-bit room key. */
export function newRawKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/**
 * Imports a raw room key. Returns { key, fingerprint, keyId }: the
 * fingerprint is shown to users, the keyId lets peers tell whether they hold
 * the same key without revealing it.
 */
export async function importRoomKey(raw) {
  if (raw.length !== 32) throw new Error("invalid room key");
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
  const fingerprint = hex(digest.subarray(0, 6)).toUpperCase().replace(/(.{4})(?!$)/g, "$1-");
  return { key, fingerprint, keyId: hex(digest.subarray(16, 32)) };
}

/**
 * 8-digit code derived from a public key ("1234-5678"). Applicant and
 * approver both display it; if the server swapped the key they differ.
 */
export async function confirmCode(pub) {
  const d = new DataView(await crypto.subtle.digest("SHA-256", pub));
  const n = String(d.getUint32(0) % 100000000).padStart(8, "0");
  return `${n.slice(0, 4)}-${n.slice(4)}`;
}

/** ECDH key pair used to hand the room key to a newcomer. */
export async function newECDH() {
  const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { priv: kp.privateKey, pub };
}

/**
 * The room's inbox key pair. Applicants encrypt pre-approval messages to its
 * public key; the private key is shared among members (exportable so it can
 * travel with the room key).
 */
export async function newInboxKey() {
  const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
  return {
    jwk: await crypto.subtle.exportKey("jwk", kp.privateKey),
    pub: b64u(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey))),
  };
}

export function importInboxKey(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]);
}

/** AES-GCM key shared with the owner of peerPub. */
export async function sharedKey(priv, peerPub) {
  const pub = await crypto.subtle.importKey("raw", peerPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  return crypto.subtle.deriveKey({ name: "ECDH", public: pub }, priv, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

/** Frames a JSON header plus optional binary body: [u32 len][header][body]. */
function pack(header, body) {
  const h = te.encode(JSON.stringify(header));
  const b = body || new Uint8Array(0);
  const out = new Uint8Array(4 + h.length + b.length);
  new DataView(out.buffer).setUint32(0, h.length);
  out.set(h, 4);
  out.set(b, 4 + h.length);
  return out;
}

function unpack(buf) {
  const n = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(0);
  const header = JSON.parse(td.decode(buf.subarray(4, 4 + n)));
  const body = buf.subarray(4 + n);
  return { header, body };
}

/** Encrypts header (+ optional bytes) into [version][iv][ciphertext]. */
export async function seal(key, header, body) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pack(header, body)));
  const out = new Uint8Array(1 + 12 + ct.length);
  out[0] = VERSION;
  out.set(iv, 1);
  out.set(ct, 13);
  return out;
}

/** Reverses seal. Throws if the data was not produced with this key. */
export async function open(key, data) {
  const buf = data instanceof Uint8Array ? data : new Uint8Array(data);
  if (buf[0] !== VERSION) throw new Error("unknown version");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.subarray(1, 13) }, key, buf.subarray(13));
  return unpack(new Uint8Array(pt));
}
