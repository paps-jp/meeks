// UI translations. The same JSON files (static/i18n/{code}.json) are used by
// the server to render the localized landing pages.

export const LANGS = [
  ["ja", "日本語"], ["en", "English"], ["ko", "한국어"], ["zh", "中文"], ["ru", "Русский"],
  ["ar", "العربية"], ["hi", "हिन्दी"], ["es", "Español"], ["bn", "বাংলা"], ["pt", "Português"],
  ["id", "Indonesia"], ["pl", "Polski"], ["uk", "Українська"],
];
export const LANG_CODES = LANGS.map(([code]) => code);
const RTL = new Set(["ar"]);
const STORE_KEY = "meeks.lang";

let dict = {};
let fallback = {};

/** The saved choice, else the browser's preferred supported language, else English. */
export function pickLang() {
  try {
    const saved = localStorage.getItem(STORE_KEY);
    if (LANG_CODES.includes(saved)) return saved;
  } catch { /* storage unavailable */ }
  for (const tag of navigator.languages || [navigator.language]) {
    const code = String(tag).toLowerCase().split("-")[0];
    if (LANG_CODES.includes(code)) return code;
  }
  return "en";
}

export function rememberLang(code) {
  try { localStorage.setItem(STORE_KEY, code); } catch { /* storage unavailable */ }
}

async function fetchDict(code) {
  try {
    const r = await fetch(`/static/i18n/${code}.json`);
    return r.ok ? await r.json() : {};
  } catch {
    return {};
  }
}

/** Loads a language and sets the document's lang / dir. */
export async function loadLang(code) {
  [dict, fallback] = await Promise.all([fetchDict(code), code === "en" ? {} : fetchDict("en")]);
  document.documentElement.lang = code;
  document.documentElement.dir = RTL.has(code) ? "rtl" : "ltr";
}

/** Translates key, filling {placeholders} from vars. */
export function t(key, vars = {}) {
  const s = dict[key] ?? fallback[key] ?? key;
  return s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}

/** Fills elements marked with data-i18n / data-i18n-placeholder / data-i18n-title. */
export function applyI18n(root = document) {
  for (const el of root.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
  for (const el of root.querySelectorAll("[data-i18n-placeholder]")) el.placeholder = t(el.dataset.i18nPlaceholder);
  for (const el of root.querySelectorAll("[data-i18n-title]")) el.title = t(el.dataset.i18nTitle);
}
