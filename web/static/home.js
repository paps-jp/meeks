import { randomId } from "./crypto.js";

// Top-level paths the server uses itself (see signaling.ValidRoomID).
const RESERVED = new Set(["static", "ws", "r", "healthz"]);
document.getElementById("room-name").addEventListener("input", (e) => e.target.setCustomValidity(""));

// Room URLs carry no key: whoever opens a new room creates it, and later
// participants receive it after a member approves them (see room.js).
document.getElementById("create").addEventListener("click", () => {
  location.href = `/${randomId(12)}`;
});

document.getElementById("custom").addEventListener("submit", (e) => {
  e.preventDefault();
  const input = document.getElementById("room-name");
  const name = input.value.trim();
  if (RESERVED.has(name.toLowerCase())) {
    input.setCustomValidity("この名前はルーム名に使えません");
    input.reportValidity();
    return;
  }
  location.href = `/${encodeURIComponent(name)}`;
});
