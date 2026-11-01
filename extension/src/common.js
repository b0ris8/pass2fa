// pass2fa — общий код popup и background. Без сети: только native messaging к локальному pass2fa.
"use strict";
const api = globalThis.browser ?? globalThis.chrome;
const HOST = "pass2fa";

async function native(msg) {
  try {
    const r = await api.runtime.sendNativeMessage(HOST, msg);
    return r ?? { ok: false, error: "пустой ответ хоста" };
  } catch (e) {
    return { ok: false, error: "pass2fa не отвечает: " + (e?.message ?? e) + " (выполни: pass2fa install-browser)" };
  }
}

function tabHost(url) {
  try {
    const u = new URL(url);
    if (!["https:", "http:"].includes(u.protocol)) return null;
    return u.hostname.toLowerCase();
  } catch { return null; }
}

// http разрешаем только для локальных адресов — пароль по открытому каналу в сеть не отправляем
function protocolAllowed(url) {
  try {
    const u = new URL(url);
    if (u.protocol === "https:") return true;
    const h = u.hostname;
    return u.protocol === "http:" && (["localhost", "127.0.0.1", "[::1]"].includes(h) || h.endsWith(".localhost"));
  } catch { return false; }
}

// ---- функции, которые выполняются В СТРАНИЦЕ (executeScript); самодостаточные, без замыканий ----

// Заполнить логин/пароль. Выполняется в каждом фрейме вкладки; заполняет только там, где хост
// совпадает с вкладкой (чужие iframe отказываются сами). Ищет и внутри open shadow DOM.
function pageFillLogin(expectHost, username, password) {
  if (location.hostname.toLowerCase() !== expectHost) return { ok: false, foreign: true };
  const deep = (root, out = []) => {
    for (const el of root.querySelectorAll("*")) {
      if (el.tagName === "INPUT") out.push(el);
      if (el.shadowRoot) deep(el.shadowRoot, out);
    }
    return out;
  };
  const visible = (el) => {
    if (el.disabled || el.readOnly || el.type === "hidden") return false;
    const r = el.getBoundingClientRect(), s = getComputedStyle(el);
    return r.width > 2 && r.height > 2 && s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0";
  };
  const set = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value")?.set;
    el.focus();
    el.dispatchEvent(new Event("focus", { bubbles: true }));
    if (setter) setter.call(el, value); else el.value = value;
    el.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: value }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.dispatchEvent(new Event("blur", { bubbles: true }));
  };
  const all = deep(document);
  const inputs = all.filter(visible);
  const textLike = (i) => ["text", "email", "tel", "", "search"].includes(i.type);
  const hint = (i) => [i.name, i.id, i.autocomplete, i.placeholder, i.getAttribute("aria-label"), i.className].join(" ");
  const isUser = (i) => textLike(i) && (i.type === "email" || /user|login|e-?mail|account|ident|phone|nick|uid/i.test(hint(i)));
  const pws = inputs.filter((i) => i.type === "password");
  const pw = pws.find((i) => i.autocomplete !== "new-password") || pws[0];
  let user = null;
  if (pw) {
    const pool = inputs.slice(0, inputs.indexOf(pw)).filter(textLike);
    user = [...pool].reverse().find(isUser) || pool[pool.length - 1] || null;
  } else {
    user = inputs.find(isUser) || null; // двухшаговый вход: сначала только логин
  }
  const filled = [];
  if (user && username) { set(user, username); filled.push("логин"); }
  if (pw && password) { set(pw, password); filled.push("пароль"); }
  if (!filled.length) {
    return { ok: false, error: `не нашёл полей входа (видимых полей: ${inputs.length} из ${all.length}, паролей: ${pws.length})` };
  }
  return { ok: true, filled };
}

function pageFillTotp(expectHost, code) {
  if (location.hostname.toLowerCase() !== expectHost) return { ok: false, foreign: true };
  const deep = (root, out = []) => {
    for (const el of root.querySelectorAll("*")) {
      if (el.tagName === "INPUT") out.push(el);
      if (el.shadowRoot) deep(el.shadowRoot, out);
    }
    return out;
  };
  const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 2 && r.height > 2 && !el.disabled && !el.readOnly && el.type !== "hidden"; };
  const inputs = deep(document).filter(visible);
  const set = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value")?.set;
    el.focus();
    if (setter) setter.call(el, value); else el.value = value;
    el.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: value }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const hint = (i) => [i.name, i.id, i.autocomplete, i.placeholder, i.getAttribute("aria-label")].join(" ");
  let el = inputs.find((i) => i.autocomplete === "one-time-code")
    || inputs.find((i) => /otp|totp|2fa|mfa|code|token|verif|pin|одноразов|код/i.test(hint(i)) && i.type !== "password")
    || (document.activeElement?.tagName === "INPUT" ? document.activeElement : null);
  const singles = inputs.filter((i) => i.maxLength === 1);
  if (!el && singles.length >= code.length) {
    singles.slice(0, code.length).forEach((i, k) => set(i, code[k]));
    return { ok: true, filled: ["код"] };
  }
  if (!el) return { ok: false, error: `не нашёл поле для кода (видимых полей: ${inputs.length})` };
  set(el, code);
  return { ok: true, filled: ["код"] };
}

// Firefox/LibreWolf без права "tabs" не отдают tab.url даже активной вкладки — читаем адрес из
// самой страницы (это разрешено тем же activeTab после клика по значку/хоткея).
async function tabWithUrl(tab) {
  if (!tab || tab.url) return tab;
  try {
    const [res] = await api.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, func: () => location.href });
    if (res?.result) return { ...tab, url: res.result };
  } catch (e) {
    return { ...tab, urlError: String(e?.message ?? e) };
  }
  return tab;
}

// почему страница недоступна — человеческим языком
function whyUnsupported(tab) {
  const u = tab?.url || "";
  if (/^(about|moz-extension|chrome|chrome-extension|edge|view-source|resource):/.test(u)) return "служебная страница браузера (" + u.slice(0, 60) + ") — сюда расширениям нельзя";
  if (/^https?:\/\/(addons\.mozilla\.org|chromewebstore\.google\.com|chrome\.google\.com\/webstore)/.test(u)) return "магазин дополнений — браузер запрещает расширениям доступ к нему";
  if (!u) return "браузер не сообщил адрес вкладки" + (tab?.urlError ? ": " + tab.urlError : "");
  return "не http/https: " + u.split(":")[0];
}

async function fillInTab(tab, func, args) {
  if (!protocolAllowed(tab.url)) return { ok: false, error: "заполняю только на https (или localhost)" };
  let results;
  try {
    // все фреймы: форма входа часто во встроенном фрейме того же сайта; чужие фреймы отказываются сами
    results = await api.scripting.executeScript({ target: { tabId: tab.id, allFrames: true }, func, args });
  } catch {
    try {
      results = await api.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, func, args });
    } catch (e) {
      const m = String(e?.message ?? e);
      const why = /addons\.mozilla\.org|Missing host permission|cannot be scripted|restricted/i.test(m)
        ? "браузер запрещает доступ к этой странице (магазин дополнений / служебная)" : m;
      return { ok: false, error: "нет доступа к странице: " + why };
    }
  }
  const rs = (results || []).map((r) => r?.result).filter(Boolean);
  const ok = rs.find((r) => r.ok);
  if (ok) return ok;
  const own = rs.filter((r) => !r.foreign);
  if (!own.length) return { ok: false, error: "страница сменилась" };
  return { ok: false, error: own[0].error + (rs.length > 1 ? ` · фреймов: ${rs.length}` : "") };
}

// код, который не истечёт прямо во время вставки
function freshCode(t) {
  return t.left <= 3 && t.next ? t.next : t.code;
}
