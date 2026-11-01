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

// Заполнить логин/пароль в верхнем фрейме. expectHost — защита от подмены вкладки между запросом и заполнением.
function pageFillLogin(expectHost, username, password) {
  const host = location.hostname.toLowerCase();
  if (host !== expectHost) return { ok: false, error: "страница сменилась" };
  const visible = (el) => {
    const r = el.getBoundingClientRect(), s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none" && !el.disabled && !el.readOnly;
  };
  const set = (el, value) => {
    const proto = Object.getPrototypeOf(el);
    const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
    el.focus();
    if (setter) setter.call(el, value); else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const inputs = [...document.querySelectorAll("input")].filter(visible);
  const pw = inputs.find((i) => i.type === "password" && i.autocomplete !== "new-password") || inputs.find((i) => i.type === "password");
  const isUser = (i) =>
    ["text", "email", "tel", ""].includes(i.type) &&
    (/(user|login|email|mail|account|ident|phone)/i.test(i.name + " " + i.id + " " + i.autocomplete + " " + (i.placeholder || "")) || i.type === "email" || i.autocomplete === "username");
  let user = null;
  if (pw) {
    // ближайшее подходящее поле ПЕРЕД паролем, предпочтительно в той же форме
    const scope = pw.form ? [...pw.form.querySelectorAll("input")].filter(visible) : inputs;
    const before = scope.slice(0, scope.indexOf(pw)).filter((i) => ["text", "email", "tel", ""].includes(i.type));
    user = before.reverse().find(isUser) || before[0] || null;
  } else {
    user = inputs.find(isUser) || null; // двухшаговый вход (Google и т.п.): сначала только логин
  }
  let filled = [];
  if (user && username) { set(user, username); filled.push("логин"); }
  if (pw && password) { set(pw, password); filled.push("пароль"); }
  if (!filled.length) return { ok: false, error: "на странице не нашёл полей входа" };
  return { ok: true, filled };
}

function pageFillTotp(expectHost, code) {
  if (location.hostname.toLowerCase() !== expectHost) return { ok: false, error: "страница сменилась" };
  const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && !el.disabled && !el.readOnly; };
  const inputs = [...document.querySelectorAll("input")].filter(visible);
  const set = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value")?.set;
    el.focus();
    if (setter) setter.call(el, value); else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  let el = inputs.find((i) => i.autocomplete === "one-time-code")
    || inputs.find((i) => /(otp|totp|2fa|mfa|code|token|verif|pin)/i.test(i.name + " " + i.id + " " + (i.placeholder || "")) && i.type !== "password")
    || (document.activeElement?.tagName === "INPUT" ? document.activeElement : null);
  // поля по одной цифре (6 инпутов maxlength=1)
  const singles = inputs.filter((i) => i.maxLength === 1);
  if (!el && singles.length >= code.length) {
    singles.slice(0, code.length).forEach((i, k) => set(i, code[k]));
    return { ok: true, filled: ["код"] };
  }
  if (!el) return { ok: false, error: "не нашёл поле для кода" };
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
  if (/^(about|moz-extension|chrome|chrome-extension|edge|view-source|resource):/.test(u)) return "служебная страница браузера — сюда расширениям нельзя";
  if (/^https?:\/\/(addons\.mozilla\.org|chromewebstore\.google\.com|chrome\.google\.com\/webstore)/.test(u)) return "магазин дополнений — браузер запрещает расширениям доступ к нему";
  if (!u) return "браузер не сообщил адрес вкладки" + (tab?.urlError ? ": " + tab.urlError : "");
  return "не http/https: " + u.split(":")[0];
}

async function fillInTab(tab, func, args) {
  if (!protocolAllowed(tab.url)) return { ok: false, error: "заполняю только на https (или localhost)" };
  try {
    // только верхний фрейм: в чужие iframe не заполняем
    const [res] = await api.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, func, args });
    return res?.result ?? { ok: false, error: "нет результата" };
  } catch (e) {
    const why = /addons\.mozilla\.org|Missing host permission|cannot be scripted|restricted/i.test(String(e?.message ?? e))
      ? "браузер запрещает доступ к этой странице (магазин дополнений / служебная)" : String(e?.message ?? e);
    return { ok: false, error: "нет доступа к странице: " + why };
  }
}

// код, который не истечёт прямо во время вставки
function freshCode(t) {
  return t.left <= 3 && t.next ? t.next : t.code;
}
