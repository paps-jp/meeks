import { randomId } from "./crypto.js";
import { LANG_CODES, rememberLang } from "./i18n.js";

// The landing page is rendered in one language; rooms opened from here use it.
rememberLang(document.documentElement.lang);

// Top-level paths the server uses itself (see signaling.ValidRoomID).
const RESERVED = new Set(["static", "ws", "r", "healthz", ...LANG_CODES]);
const input = document.getElementById("room-name");
input.addEventListener("input", () => input.setCustomValidity(""));

// Room URLs carry no key: whoever opens a new room creates it, and later
// participants receive it after a member approves them (see room.js).
document.getElementById("create").addEventListener("click", () => {
  location.href = `/${randomId(12)}`;
});

document.getElementById("custom").addEventListener("submit", (e) => {
  e.preventDefault();
  const name = input.value.trim();
  if (RESERVED.has(name)) {
    input.setCustomValidity(input.dataset.reservedMsg);
    input.reportValidity();
    return;
  }
  location.href = `/${encodeURIComponent(name)}`;
});
