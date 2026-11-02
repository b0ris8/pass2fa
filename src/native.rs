//! Native messaging host для браузерного расширения. Браузер сам запускает pass2fa на запрос
//! (stdin/stdout: 4 байта длины в порядке хоста + JSON) и закрывает его — фонового процесса нет.
//! Операции: status, unlock {password}, lock, get {url} → логины для хоста вкладки + TOTP.
//! Сравнение хоста строгое: точное совпадение или поддомен сохранённого (по границе метки).
use crate::model::{LoginEntry, TotpEntry, Vault};
use crate::{icons, session, totp, vault};
use age::secrecy::SecretString;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const HOST_NAME: &str = "pass2fa";
pub const FIREFOX_EXT_ID: &str = "pass2fa@b0ris8";
pub const CHROMIUM_EXT_ID: &str = "mppimlmnkoibdoennahbdmclgegncjed";
const MAX_IN: usize = 64 * 1024; // от браузера приходят маленькие запросы

/// Нас запустил браузер? Firefox/LibreWolf: argv[1] — путь к манифесту, argv[2] — id расширения
/// (на Windows путь произвольный — проверяем id); Chromium: argv[1] — "chrome-extension://<id>/".
pub fn invoked_by_browser(args: &[String]) -> bool {
    args.first().is_some_and(|a| a.starts_with("chrome-extension://"))
        || args.get(1).is_some_and(|a| a == FIREFOX_EXT_ID)
        || args.first().is_some_and(|a| a.ends_with(".json") && a.contains("ative") && a.contains(HOST_NAME))
}

fn read_msg(r: &mut impl Read) -> Option<Value> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).ok()?;
    let n = u32::from_ne_bytes(len) as usize;
    if n == 0 || n > MAX_IN {
        return None;
    }
    let mut buf = zeroize::Zeroizing::new(vec![0u8; n]);
    r.read_exact(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

fn write_msg(w: &mut impl Write, v: &Value) -> std::io::Result<()> {
    let s = zeroize::Zeroizing::new(serde_json::to_vec(v).unwrap_or_default());
    w.write_all(&(s.len() as u32).to_ne_bytes())?;
    w.write_all(&s)?;
    w.flush()
}

pub fn run(vault_path: &Path) {
    let (mut i, mut o) = (std::io::stdin().lock(), std::io::stdout().lock());
    while let Some(req) = read_msg(&mut i) {
        let resp = handle(vault_path, &req);
        if write_msg(&mut o, &resp).is_err() {
            break;
        }
    }
}

fn err(m: impl Into<String>) -> Value {
    json!({ "ok": false, "error": m.into() })
}

pub fn handle(vault_path: &Path, req: &Value) -> Value {
    match req.get("op").and_then(Value::as_str).unwrap_or("") {
        "status" => json!({ "ok": true, "unlocked": session::is_unlocked(), "supported": session::supported() }),
        "lock" => {
            session::clear();
            json!({ "ok": true })
        }
        "unlock" => {
            let Some(p) = req.get("password").and_then(Value::as_str) else { return err("нет пароля") };
            let pass = SecretString::from(p.to_string());
            match vault::unlock(vault_path, &pass) {
                Ok((_, id)) => match session::publish(&id) {
                    Ok(()) => json!({ "ok": true }),
                    Err(e) => err(e),
                },
                Err(e) => err(e),
            }
        }
        "get" => {
            let Some(url) = req.get("url").and_then(Value::as_str) else { return err("нет url") };
            let Some(tab) = endpoint(url) else { return err("не разобрал адрес") };
            match session::load(vault_path) {
                Ok(None) => json!({ "ok": false, "locked": true }),
                Err(e) => err(e),
                Ok(Some((v, _))) => found(&v, &tab),
            }
        }
        other => err(format!("неизвестная операция: {other}")),
    }
}

/// Хост и порт из адреса. Порт: явный, иначе стандартный для схемы (https 443, http 80);
/// без схемы и без порта — None (совпадает с любым портом).
#[derive(Debug, Clone, PartialEq)]
pub struct Endpoint {
    pub host: String,
    pub port: Option<u16>,
}

pub fn endpoint(url: &str) -> Option<Endpoint> {
    let u = url.trim();
    let (scheme, rest) = match u.split_once("://") {
        Some((s, r)) => (Some(s.to_lowercase()), r),
        None => (None, u),
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?; // user:pass@host
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h, p.parse::<u16>().ok()),
        _ => (authority, None),
    };
    let host = host.trim_start_matches("www.").to_lowercase();
    if host.is_empty() || !host.contains('.') && host != "localhost" {
        return None;
    }
    let port = port.or(match scheme.as_deref() {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    });
    Some(Endpoint { host, port })
}

fn found(v: &Vault, tab: &Endpoint) -> Value {
    // (точное совпадение хоста+порта — первым, затем поддомены, затем равнозначные домены)
    let mut hits: Vec<(u8, &LoginEntry)> = v
        .passwords
        .iter()
        .filter_map(|l| login_rank(l, tab, &v.equiv).map(|r| (r, l)))
        .collect();
    hits.sort_by_key(|(r, l)| (*r, l.name.to_lowercase()));
    let logins: Vec<Value> = hits
        .into_iter()
        .map(|(_, l)| json!({ "name": l.name, "username": l.username, "password": l.password, "group": l.group }))
        .collect();
    let host = &tab.host;
    let now = totp::now();
    let codes: Vec<Value> = v
        .codes
        .iter()
        .filter(|c| code_matches(c, tab, &v.equiv))
        .filter_map(|c| {
            let (code, left) = totp::code_at(c, now)?;
            // следующий код — чтобы расширение не вставило истекающий (left ≤ 3 с)
            let (next, _) = totp::code_at(c, now + c.period.max(1))?;
            Some(json!({ "name": c.name, "code": code, "left": left, "next": next, "period": c.period }))
        })
        .collect();
    let shown = match tab.port {
        Some(443) | Some(80) | None => host.clone(),
        Some(p) => format!("{host}:{p}"),
    };
    json!({ "ok": true, "host": shown, "logins": logins, "totp": codes })
}

/// Адреса записи: URL + доп. сайты; если URL пуст — имя, когда оно похоже на домен (CSV часто кладёт домен в name).
fn entry_endpoints(l: &LoginEntry) -> Vec<Endpoint> {
    let mut out: Vec<Endpoint> = endpoint(&l.url)
        .or_else(|| {
            let n = l.name.trim();
            (l.url.trim().is_empty() && n.contains('.') && !n.contains(' ') && !n.contains('@')).then(|| endpoint(n)).flatten()
        })
        .into_iter()
        .collect();
    out.extend(l.extra_sites.iter().filter_map(|s| endpoint(s)));
    out
}

fn login_rank(l: &LoginEntry, tab: &Endpoint, equiv: &[Vec<String>]) -> Option<u8> {
    entry_endpoints(l).iter().filter_map(|e| endpoint_rank(e, tab, equiv)).min()
}

/// Группа равнозначных доменов, к которой относится хост (сам домен группы или его поддомен).
fn equiv_group<'a>(equiv: &'a [Vec<String>], host: &str) -> Option<&'a Vec<String>> {
    equiv.iter().find(|g| g.iter().any(|d| host_matches(d, host)))
}

/// 0 — тот же хост и порт, 1 — поддомен сохранённого, 2 — равнозначный домен; None — не подходит.
/// Порт обязан совпасть, если он известен у обоих (dev1step.com:6493 ≠ dev1step.com).
/// Равнозначность — только когда сохранён сам домен группы (proton.me), а не чей-то поддомен
/// (tenant.example.net не «наследует» всю группу).
fn endpoint_rank(saved: &Endpoint, tab: &Endpoint, equiv: &[Vec<String>]) -> Option<u8> {
    if let (Some(a), Some(b)) = (saved.port, tab.port) {
        if a != b {
            return None;
        }
    }
    if host_matches(&saved.host, &tab.host) {
        return Some(if saved.host == tab.host { 0 } else { 1 });
    }
    let g = equiv.iter().find(|g| g.iter().any(|d| d.trim_start_matches("www.") == saved.host))?;
    g.iter().any(|d| host_matches(d, &tab.host)).then_some(2)
}

/// Точное совпадение или вкладка — поддомен сохранённого хоста (по границе метки).
/// id.atlassian.com ≠ atlassian.com.evil.io; accounts.google.com ⊂ google.com.
pub fn host_matches(saved: &str, tab: &str) -> bool {
    let (s, t) = (saved.trim().trim_start_matches("www."), tab.trim_start_matches("www."));
    !s.is_empty() && (s == t || t.ends_with(&format!(".{s}")))
}

/// Метка сервиса в домене: github.com → «github», account.proton.me → «proton».
fn service_label(host: &str) -> Option<&str> {
    let labels: Vec<&str> = host.split('.').collect();
    let l = labels.len().checked_sub(2).map(|i| labels[i])?;
    (l.len() >= 3).then_some(l)
}

/// TOTP: если у записи заданы сайты — строго по хосту и порту (как логины, с равнозначными доменами).
/// Иначе — только по issuer (название сервиса) против метки домена вкладки и равнозначных ему доменов:
/// issuer «Proton» подходит к proton.me и protonmail.com, «Anthropic» — к claude.ai.
/// Имя аккаунта/почта НЕ участвуют — иначе код «…@protonmail.com» всплывал бы на любом сайте с этой почтой.
fn code_matches(c: &TotpEntry, tab: &Endpoint, equiv: &[Vec<String>]) -> bool {
    let sites: Vec<Endpoint> = c.sites.iter().filter_map(|s| endpoint(s)).collect();
    if !sites.is_empty() {
        return sites.iter().any(|s| endpoint_rank(s, tab, equiv).is_some());
    }
    // issuer; если пуст — имя без «(аккаунт)» и без слов с @
    let service = if c.issuer.trim().is_empty() {
        let head = c.name.split('(').next().unwrap_or("");
        head.split_whitespace().filter(|w| !w.contains('@')).collect::<Vec<_>>().join(" ")
    } else {
        c.issuer.clone()
    };
    let hay = icons::norm(&service);
    if hay.is_empty() {
        return false;
    }
    let mut labels: Vec<&str> = service_label(&tab.host).into_iter().collect();
    if let Some(g) = equiv_group(equiv, &tab.host) {
        labels.extend(g.iter().filter_map(|d| service_label(d.trim_start_matches("www."))));
    }
    labels.iter().any(|l| hay.contains(&icons::norm(l)))
}

/// Разбор поля «по одному на строку» (также через пробел/запятую) → список адресов.
pub fn parse_sites(text: &str) -> Vec<String> {
    text.split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Разбор групп равнозначных доменов: строка = группа, домены через пробел/запятую; группы из одного домена отбрасываются.
pub fn parse_equiv(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .map(|l| {
            l.split(|c: char| c.is_whitespace() || c == ',' || c == ';')
                .filter_map(|d| endpoint(d).map(|e| e.host))
                .fold(Vec::<String>::new(), |mut acc, h| {
                    if !acc.contains(&h) {
                        acc.push(h);
                    }
                    acc
                })
        })
        .filter(|g| g.len() >= 2)
        .collect()
}

// ---------- установка манифестов хоста ----------
// Манифест указывает на текущий бинарник (current_exe): `pass2fa install` сначала копирует себя
// в постоянное место и запускает install-browser уже оттуда.

/// Хост + расширение (pass2fa-firefox.xpi и chromium/ — из встроенных в бинарник файлов).
pub fn install() -> Result<Vec<PathBuf>, String> {
    let mut out = install_host()?;
    let (xpi, ch) = crate::bundle::write(&crate::bundle::dir())?;
    out.push(xpi);
    out.push(ch);
    Ok(out)
}

pub fn uninstall() -> Vec<PathBuf> {
    let mut v = uninstall_host();
    v.extend(crate::bundle::remove(&crate::bundle::dir()));
    v
}

#[cfg(unix)]
fn manifest_dirs() -> Vec<(PathBuf, bool)> {
    // (папка, это Firefox-семейство?)
    let home = dirs::home_dir().unwrap_or_default();
    let cfg = dirs::config_dir().unwrap_or_else(|| home.join(".config"));
    let mut v = vec![
        (home.join(".mozilla/native-messaging-hosts"), true),
        (home.join(".librewolf/native-messaging-hosts"), true),
        (cfg.join("chromium/NativeMessagingHosts"), false),
        (cfg.join("google-chrome/NativeMessagingHosts"), false),
        (cfg.join("BraveSoftware/Brave-Browser/NativeMessagingHosts"), false),
        (cfg.join("vivaldi/NativeMessagingHosts"), false),
    ];
    // ставим только туда, где браузер есть (его профиль существует); Firefox — всегда
    v.retain(|(d, ff)| *ff && d.starts_with(home.join(".mozilla")) || d.parent().is_some_and(Path::exists));
    v
}

fn manifest(exe: &str, firefox: bool) -> Value {
    let mut m = json!({
        "name": HOST_NAME,
        "description": "pass2fa — локальные пароли и TOTP",
        "path": exe,
        "type": "stdio",
    });
    if firefox {
        m["allowed_extensions"] = json!([FIREFOX_EXT_ID]);
    } else {
        m["allowed_origins"] = json!([format!("chrome-extension://{CHROMIUM_EXT_ID}/")]);
    }
    m
}

fn write_manifest(p: &Path, exe: &str, firefox: bool) -> Result<(), String> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    // UTF-8 без BOM — путь может быть с кириллицей (C:\Users\Администратор\…)
    std::fs::write(p, serde_json::to_string_pretty(&manifest(exe, firefox)).unwrap()).map_err(|e| format!("{}: {e}", p.display()))
}

fn current_exe() -> Result<String, String> {
    std::env::current_exe().map(|p| p.display().to_string()).map_err(|e| e.to_string())
}

#[cfg(unix)]
fn install_host() -> Result<Vec<PathBuf>, String> {
    let exe = current_exe()?;
    let mut out = Vec::new();
    for (dir, ff) in manifest_dirs() {
        let p = dir.join(format!("{HOST_NAME}.json"));
        write_manifest(&p, &exe, ff)?;
        out.push(p);
    }
    Ok(out)
}

#[cfg(unix)]
fn uninstall_host() -> Vec<PathBuf> {
    manifest_dirs()
        .into_iter()
        .map(|(d, _)| d.join(format!("{HOST_NAME}.json")))
        .filter(|p| std::fs::remove_file(p).is_ok())
        .collect()
}

// Windows: браузеры ищут манифест не по папке, а по ключу реестра HKCU\…\NativeMessagingHosts\pass2fa
// (значение по умолчанию = путь к манифесту). Firefox-семейство: ключ Mozilla (LibreWolf — его же,
// ключ LibreWolf — на всякий случай); Chromium-семейство читает ключ Chrome/Chromium.
#[cfg(windows)]
const REG_KEYS: [(&str, bool); 4] = [
    (r"HKCU\Software\Mozilla\NativeMessagingHosts\pass2fa", true),
    (r"HKCU\Software\LibreWolf\NativeMessagingHosts\pass2fa", true),
    (r"HKCU\Software\Google\Chrome\NativeMessagingHosts\pass2fa", false),
    (r"HKCU\Software\Chromium\NativeMessagingHosts\pass2fa", false),
];

#[cfg(windows)]
fn win_manifests() -> Result<(PathBuf, PathBuf), String> {
    let d = dirs::data_local_dir().ok_or("нет %LOCALAPPDATA%")?.join("pass2fa").join("NativeMessagingHosts");
    Ok((d.join(format!("{HOST_NAME}.json")), d.join(format!("{HOST_NAME}.chromium.json"))))
}

#[cfg(windows)]
fn reg(args: &[&str]) -> Result<(), String> {
    let o = std::process::Command::new("reg").args(args).output().map_err(|e| format!("reg: {e}"))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(format!("reg {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim()))
    }
}

#[cfg(windows)]
fn install_host() -> Result<Vec<PathBuf>, String> {
    let exe = current_exe()?;
    let (ff, ch) = win_manifests()?;
    write_manifest(&ff, &exe, true)?;
    write_manifest(&ch, &exe, false)?;
    for (key, firefox) in REG_KEYS {
        let m = if firefox { &ff } else { &ch };
        reg(&["add", key, "/ve", "/t", "REG_SZ", "/d", &m.display().to_string(), "/f"])?;
    }
    Ok(vec![ff, ch])
}

#[cfg(windows)]
fn uninstall_host() -> Vec<PathBuf> {
    for (key, _) in REG_KEYS {
        let _ = reg(&["delete", key, "/f"]);
    }
    let Ok((ff, ch)) = win_manifests() else { return vec![] };
    [ff, ch].into_iter().filter(|p| std::fs::remove_file(p).is_ok()).collect()
}

#[cfg(not(any(unix, windows)))]
fn install_host() -> Result<Vec<PathBuf>, String> {
    Err("эта ОС не поддерживается".into())
}
#[cfg(not(any(unix, windows)))]
fn uninstall_host() -> Vec<PathBuf> {
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_hosts() {
        assert!(host_matches("github.com", "github.com"));
        assert!(host_matches("google.com", "accounts.google.com"));
        assert!(host_matches("www.paypal.com", "paypal.com"));
        assert!(!host_matches("atlassian.com", "atlassian.com.evil.io"));
        assert!(!host_matches("id.atlassian.com", "atlassian.com"));
        assert!(!host_matches("hub.com", "github.com"));
        assert!(!host_matches("", "github.com"));
    }

    #[test]
    fn framing_roundtrip() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &json!({"op":"status"})).unwrap();
        let v = read_msg(&mut &buf[..]).unwrap();
        assert_eq!(v["op"], "status");
        // слишком длинное сообщение отвергается
        let mut big = (MAX_IN as u32 + 1).to_ne_bytes().to_vec();
        big.extend(vec![b' '; 10]);
        assert!(read_msg(&mut &big[..]).is_none());
    }

    #[test]
    fn find_for_host() {
        let mut v = Vault::default();
        let mk = |name: &str, url: &str| LoginEntry { name: name.into(), url: url.into(), username: "u".into(), password: "p".into(), note: String::new(), icon: None, group: String::new(), extra_sites: Vec::new() };
        v.passwords.push(mk("GitHub", "https://github.com/login"));
        v.passwords.push(mk("accounts.google.com", ""));
        v.passwords.push(mk("Evil", "https://github.com.evil.io"));
        let mut c = TotpEntry::new("GitHub (b0ris8)", "JBSWY3DPEHPK3PXP");
        c.issuer = "GitHub".into();
        v.codes.push(c);
        v.codes.push(TotpEntry::new("Google (me)", "GEZDGNBVGY3TQOJQ"));
        let ep = |u: &str| endpoint(u).unwrap();
        let r = found(&v, &ep("https://github.com/login"));
        assert_eq!(r["logins"].as_array().unwrap().len(), 1);
        assert_eq!(r["totp"].as_array().unwrap().len(), 1);
        let r = found(&v, &ep("https://accounts.google.com/x"));
        assert_eq!(r["logins"].as_array().unwrap().len(), 1);
        assert_eq!(r["logins"][0]["name"], "accounts.google.com");
        assert_eq!(r["totp"].as_array().unwrap().len(), 1);
        let r = found(&v, &ep("https://gist.github.com/"));
        assert_eq!(r["logins"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn totp_not_by_account_email() {
        let mut v = Vault::default();
        // Proton-аккаунт с почтой на protonmail.com; GitHub-аккаунт с той же почтой
        let mut p = TotpEntry::new("b0ris8@protonmail.com", "JBSWY3DPEHPK3PXP");
        p.issuer = "Proton".into();
        let mut g = TotpEntry::new("GitHub (b0ris8@protonmail.com)", "GEZDGNBVGY3TQOJQ");
        g.issuer = "GitHub".into();
        let mut l = TotpEntry::new("LinkedIn (b.vasilica@1step.md)", "JBSWY3DPEHPK3PXQ");
        l.issuer = "LinkedIn".into();
        // явный сайт с портом
        let mut gr = TotpEntry::new("Grafana", "JBSWY3DPEHPK3PXR");
        gr.sites = vec!["https://dev1step.com:6493".into()];
        v.codes.extend([p, g, l, gr]);
        let codes = |u: &str| -> Vec<String> {
            found(&v, &endpoint(u).unwrap())["totp"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap().to_string()).collect()
        };
        assert_eq!(codes("https://github.com/login"), vec!["GitHub (b0ris8@protonmail.com)"]);
        assert_eq!(codes("https://account.proton.me/login"), vec!["b0ris8@protonmail.com"]);
        assert_eq!(codes("https://mail.protonmail.com/"), vec!["b0ris8@protonmail.com"]); // proton.me ≡ protonmail.com
        assert!(codes("https://1step.md/").is_empty());          // почта аккаунта не притягивает код
        assert_eq!(codes("https://dev1step.com:6493/login"), vec!["Grafana"]);
        assert!(codes("https://dev1step.com/").is_empty());
    }

    #[test]
    fn equivalent_domains() {
        let mut v = Vault::default();
        let mk = |name: &str, url: &str| LoginEntry { name: name.into(), url: url.into(), username: name.into(), password: "p".into(), note: String::new(), icon: None, group: String::new(), extra_sites: Vec::new() };
        v.passwords.push(mk("Proton", "https://account.proton.me"));
        v.passwords.push(mk("Proton root", "https://proton.me"));
        let mut oa = mk("OpenAI", "https://platform.openai.com");
        oa.extra_sites = vec!["chatgpt.com".into()];
        v.passwords.push(oa);
        let mut a = TotpEntry::new("b0ris8@protonmail.com", "JBSWY3DPEHPK3PXP");
        a.issuer = "Anthropic".into();
        let mut o = TotpEntry::new("OpenAI (me)", "GEZDGNBVGY3TQOJQ");
        o.sites = vec!["https://auth.openai.com".into(), "chatgpt.com".into()];
        v.codes.extend([a, o]);
        let names = |v: &Vault, u: &str, k: &str| -> Vec<String> {
            found(v, &endpoint(u).unwrap())[k].as_array().unwrap().iter().map(|l| l["name"].as_str().unwrap().to_string()).collect()
        };
        // сохранён корень группы → работает на равнозначных; поддомен (account.proton.me) — только сам
        assert_eq!(names(&v, "https://mail.protonmail.com/", "logins"), vec!["Proton root"]);
        assert_eq!(names(&v, "https://account.proton.me/", "logins"), vec!["Proton", "Proton root"]);
        assert_eq!(names(&v, "https://chatgpt.com/auth", "logins"), vec!["OpenAI"]);
        assert_eq!(names(&v, "https://openai.com/", "logins"), vec!["OpenAI"]); // доп. сайт chatgpt.com — корень группы
        assert_eq!(names(&v, "https://claude.ai/login", "totp"), vec!["b0ris8@protonmail.com"]);
        assert_eq!(names(&v, "https://console.anthropic.com/", "totp"), vec!["b0ris8@protonmail.com"]);
        assert_eq!(names(&v, "https://chatgpt.com/", "totp"), vec!["OpenAI (me)"]);
        assert_eq!(names(&v, "https://openai.com/", "totp"), vec!["OpenAI (me)"]); // сайт chatgpt.com ≡ openai.com
        assert!(names(&v, "https://github.com/", "totp").is_empty());
        assert!(names(&v, "https://proton.me/", "totp").is_empty());
        // без групп — равнозначности нет
        v.equiv.clear();
        assert!(names(&v, "https://claude.ai/login", "totp").is_empty());
        assert!(names(&v, "https://mail.protonmail.com/", "logins").is_empty());
    }

    #[test]
    fn parse_lists() {
        assert_eq!(parse_sites("a.com\n https://b.com:8443/x , c.io"), vec!["a.com", "https://b.com:8443/x", "c.io"]);
        assert_eq!(
            parse_equiv("proton.me, https://www.protonmail.com/\nsolo.com\n\nopenai.com chatgpt.com chatgpt.com"),
            vec![vec!["proton.me".to_string(), "protonmail.com".into()], vec!["openai.com".into(), "chatgpt.com".into()]]
        );
    }

    #[test]
    fn ports() {
        let mk = |name: &str, url: &str| LoginEntry { name: name.into(), url: url.into(), username: name.into(), password: "p".into(), note: String::new(), icon: None, group: String::new(), extra_sites: Vec::new() };
        let mut v = Vault::default();
        v.passwords.push(mk("grafana", "https://dev1step.com:6493/login"));
        v.passwords.push(mk("apache", "https://dev1step.com/"));
        v.passwords.push(mk("jupyter", "https://dev1step.com:8888"));
        let names = |u: &str| -> Vec<String> {
            found(&v, &endpoint(u).unwrap())["logins"].as_array().unwrap().iter().map(|l| l["name"].as_str().unwrap().to_string()).collect()
        };
        assert_eq!(names("https://dev1step.com:6493/login"), vec!["grafana"]);
        assert_eq!(names("https://dev1step.com/admin"), vec!["apache"]);
        assert_eq!(names("https://dev1step.com:443/"), vec!["apache"]); // явный стандартный порт = без порта
        assert_eq!(names("http://dev1step.com:8888/lab"), vec!["jupyter"]);
        assert!(names("https://dev1step.com:9999/").is_empty());
        assert_eq!(endpoint("https://user:pw@Example.COM:8443/x").unwrap(), Endpoint { host: "example.com".into(), port: Some(8443) });
    }

    #[test]
    fn detect_invocation() {
        assert!(invoked_by_browser(&["/home/u/.mozilla/native-messaging-hosts/pass2fa.json".into(), "pass2fa@b0ris8".into()]));
        assert!(invoked_by_browser(&["chrome-extension://abc/".into()]));
        // Windows: манифест в произвольной папке — узнаём по id расширения
        assert!(invoked_by_browser(&[r"C:\Users\Администратор\AppData\Local\pass2fa\pass2fa.json".into(), FIREFOX_EXT_ID.into()]));
        assert!(!invoked_by_browser(&["import".into(), "x.json".into()]));
    }
}
