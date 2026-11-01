"use strict";
const $ = (id) => document.getElementById(id);
let tab = null, host = null, data = null;

function msg(text, err = false) {
  $("msg").textContent = text || "";
  $("msg").className = "msg" + (err ? " err" : "");
}

async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    msg(`${what} скопирован`);
  } catch (e) { msg("буфер недоступен: " + e, true); }
}

async function targetTab() {
  // ?tab=<id> — для автотестов, когда popup открыт как вкладка
  const t = new URLSearchParams(location.search).get("tab");
  if (t) return api.tabs.get(Number(t));
  const [x] = await api.tabs.query({ active: true, currentWindow: true });
  return x;
}

function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  Object.assign(e, props);
  kids.forEach((k) => e.append(k));
  return e;
}

function render() {
  $("unlock").hidden = true;
  $("list").hidden = false;
  $("lock").hidden = false;
  const L = $("logins"), T = $("totp");
  L.replaceChildren(); T.replaceChildren();
  for (const l of data.logins) {
    const who = el("div", { className: "who" }, el("b", { textContent: l.username || "(без логина)" }), el("small", { textContent: l.group ? `${l.name} · ${l.group}` : l.name }));
    const fill = el("button", { className: "primary", textContent: "Заполнить", title: "вставить логин и пароль" });
    fill.onclick = async () => {
      const r = await fillInTab(tab, pageFillLogin, [host, l.username, l.password]);
      if (r.ok) window.close(); else msg(r.error, true);
    };
    const cu = el("button", { className: "icon", textContent: "👤", title: "копировать логин" });
    cu.onclick = () => copy(l.username, "Логин");
    const cp = el("button", { className: "icon", textContent: "🔑", title: "копировать пароль" });
    cp.onclick = () => copy(l.password, "Пароль");
    L.append(el("li", {}, who, cu, cp, fill));
  }
  for (const t of data.totp) {
    const code = freshCode(t);
    const who = el("div", { className: "who" }, el("b", { textContent: t.name }), el("small", { textContent: t.left <= 3 ? "следующий код" : `ещё ${t.left} с` }));
    const c = el("span", { className: "code" + (t.left <= 5 ? " warn" : ""), textContent: code.replace(/^(\d{3})(\d+)$/, "$1 $2") });
    const fill = el("button", { className: "primary", textContent: "Вставить", title: "вставить код в поле" });
    fill.onclick = async () => {
      const r = await fillInTab(tab, pageFillTotp, [host, code]);
      if (r.ok) window.close(); else msg(r.error, true);
    };
    const cc = el("button", { className: "icon", textContent: "📋", title: "копировать код" });
    cc.onclick = () => copy(code, "Код");
    T.append(el("li", {}, who, c, cc, fill));
  }
  $("logins-h").hidden = !data.logins.length;
  $("totp-h").hidden = !data.totp.length;
  $("empty").hidden = !!(data.logins.length || data.totp.length);
}

async function load() {
  msg("");
  data = await native({ op: "get", url: tab.url });
  if (data.locked) {
    $("list").hidden = true;
    $("lock").hidden = true;
    $("unlock").hidden = false;
    $("pass").focus();
    return;
  }
  if (!data.ok) return msg(data.error, true);
  render();
}

async function main() {
  tab = await tabWithUrl(await targetTab());
  host = tab && tabHost(tab.url);
  $("host").textContent = host || "эта страница не поддерживается";
  if (!host) return msg(whyUnsupported(tab), true);
  if (!protocolAllowed(tab.url)) msg("заполнение только на https; копировать можно", true);
  await load();
}

$("unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const p = $("pass").value;
  if (!p) return;
  msg("проверяю…");
  const r = await native({ op: "unlock", password: p });
  $("pass").value = "";
  if (!r.ok) { msg(r.error, true); $("pass").focus(); return; }
  await load();
});
$("pass").addEventListener("input", () => { $("layout").hidden = !/[Ѐ-ӿ]/.test($("pass").value); });
$("eye").onclick = () => { const p = $("pass"); p.type = p.type === "password" ? "text" : "password"; p.focus(); };
$("lock").onclick = async () => { await native({ op: "lock" }); data = null; await load(); msg("заблокировано"); };

main();
