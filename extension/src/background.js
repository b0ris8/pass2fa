// pass2fa — фон: горячие клавиши. Заполнение только по действию пользователя, не при загрузке страницы.
"use strict";
if (typeof importScripts === "function") importScripts("common.js"); // Chromium service worker

async function activeTab() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  return tabWithUrl(tab);
}

async function openPopup() {
  try { await api.action.openPopup(); } catch { /* старые версии браузера: только по клику на значок */ }
}

function badge(text, ok) {
  api.action.setBadgeBackgroundColor?.({ color: ok ? "#A3BE8C" : "#BF616A" });
  api.action.setBadgeText({ text });
  setTimeout(() => api.action.setBadgeText({ text: "" }), 2500);
}

async function quickFill(kind) {
  const tab = await activeTab();
  const host = tab && tabHost(tab.url);
  if (!host) return badge("—", false);
  const r = await native({ op: "get", url: tab.url });
  if (r.locked) return openPopup(); // надо разблокировать — в popup
  if (!r.ok) return badge("!", false);
  if (kind === "login") {
    if (r.logins.length !== 1) return r.logins.length ? openPopup() : badge("0", false); // несколько — выбрать в popup
    const l = r.logins[0];
    const res = await fillInTab(tab, pageFillLogin, [host, l.username, l.password]);
    badge(res.ok ? "✓" : "!", res.ok);
  } else {
    if (r.totp.length !== 1) return r.totp.length ? openPopup() : badge("0", false);
    const res = await fillInTab(tab, pageFillTotp, [host, freshCode(r.totp[0])]);
    badge(res.ok ? "✓" : "!", res.ok);
  }
}

api.commands.onCommand.addListener((cmd) => {
  if (cmd === "fill-login") quickFill("login");
  if (cmd === "fill-totp") quickFill("totp");
});

// для автотестов (e2e): заполнить первую запись в указанной вкладке
globalThis.pass2faTestFill = async (tabId) => {
  const tab = await api.tabs.get(tabId);
  const r = await native({ op: "get", url: tab.url });
  if (!r.ok || !r.logins.length) return r;
  return fillInTab(tab, pageFillLogin, [tabHost(tab.url), r.logins[0].username, r.logins[0].password]);
};
