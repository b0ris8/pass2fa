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

/// Нас запустил браузер? Firefox: argv[1] — путь к манифесту, argv[2] — id расширения;
/// Chromium: argv[1] — "chrome-extension://<id>/".
pub fn invoked_by_browser(args: &[String]) -> bool {
    args.first().is_some_and(|a| {
        a.starts_with("chrome-extension://") || (a.ends_with(".json") && a.contains("ative") && a.contains(HOST_NAME))
    })
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
        "status" => json!({ "ok": true, "unlocked": session::passphrase().is_some(), "supported": session::supported() }),
        "lock" => {
            session::clear();
            json!({ "ok": true })
        }
        "unlock" => {
            let Some(p) = req.get("password").and_then(Value::as_str) else { return err("нет пароля") };
            let pass = SecretString::from(p.to_string());
            match vault::load(vault_path, &pass) {
                Ok(v) => match session::publish(vault_path, &pass, &v) {
                    Ok(()) => json!({ "ok": true }),
                    Err(e) => err(e),
                },
                Err(e) => err(e),
            }
        }
        "get" => {
            let Some(url) = req.get("url").and_then(Value::as_str) else { return err("нет url") };
            let Some(host) = icons::host(url).or_else(|| url.split("://").nth(1).map(|h| h.split(['/', ':']).next().unwrap_or("").to_lowercase())) else {
                return err("не разобрал хост");
            };
            match session::load(vault_path) {
                Ok(None) => json!({ "ok": false, "locked": true }),
                Err(e) => err(e),
                Ok(Some(v)) => found(&v, &host),
            }
        }
        other => err(format!("неизвестная операция: {other}")),
    }
}

fn found(v: &Vault, host: &str) -> Value {
    let logins: Vec<Value> = v
        .passwords
        .iter()
        .filter(|l| login_matches(l, host))
        .map(|l| json!({ "name": l.name, "username": l.username, "password": l.password, "group": l.group }))
        .collect();
    let now = totp::now();
    let codes: Vec<Value> = v
        .codes
        .iter()
        .filter(|c| code_matches(c, host))
        .filter_map(|c| {
            let (code, left) = totp::code_at(c, now)?;
            // следующий код — чтобы расширение не вставило истекающий (left ≤ 3 с)
            let (next, _) = totp::code_at(c, now + c.period.max(1))?;
            Some(json!({ "name": c.name, "code": code, "left": left, "next": next, "period": c.period }))
        })
        .collect();
    json!({ "ok": true, "host": host, "logins": logins, "totp": codes })
}

/// Хост записи: из URL, иначе из имени, если оно похоже на домен (CSV часто кладёт домен в name).
fn entry_host(l: &LoginEntry) -> Option<String> {
    icons::host(&l.url).or_else(|| {
        let n = l.name.trim().to_lowercase();
        (n.contains('.') && !n.contains(' ') && !n.contains('@')).then(|| n.trim_start_matches("www.").to_string())
    })
}

/// Точное совпадение или вкладка — поддомен сохранённого хоста (по границе метки).
/// id.atlassian.com ≠ atlassian.com.evil.io; accounts.google.com ⊂ google.com.
pub fn host_matches(saved: &str, tab: &str) -> bool {
    let (s, t) = (saved.trim_start_matches("www."), tab.trim_start_matches("www."));
    !s.is_empty() && (s == t || t.ends_with(&format!(".{s}")))
}

fn login_matches(l: &LoginEntry, host: &str) -> bool {
    entry_host(l).is_some_and(|h| host_matches(&h, host))
}

/// TOTP без URL: совпадение по метке домена второго уровня (github.com → «github») в issuer/имени.
fn code_matches(c: &TotpEntry, host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    let Some(label) = labels.len().checked_sub(2).map(|i| labels[i]) else { return false };
    if label.len() < 3 {
        return false;
    }
    let hay = icons::norm(&format!("{} {}", c.issuer, c.name));
    hay.contains(&icons::norm(label))
}

// ---------- установка манифестов хоста ----------
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

#[cfg(unix)]
pub fn install() -> Result<Vec<PathBuf>, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?.display().to_string();
    let mut out = Vec::new();
    for (dir, ff) in manifest_dirs() {
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let p = dir.join(format!("{HOST_NAME}.json"));
        std::fs::write(&p, serde_json::to_string_pretty(&manifest(&exe, ff)).unwrap()).map_err(|e| format!("{}: {e}", p.display()))?;
        out.push(p);
    }
    Ok(out)
}

#[cfg(unix)]
pub fn uninstall() -> Vec<PathBuf> {
    manifest_dirs()
        .into_iter()
        .map(|(d, _)| d.join(format!("{HOST_NAME}.json")))
        .filter(|p| std::fs::remove_file(p).is_ok())
        .collect()
}

#[cfg(not(unix))]
pub fn install() -> Result<Vec<PathBuf>, String> {
    Err("на Windows пока не реализовано (нужен ключ реестра HKCU\\Software\\Mozilla\\NativeMessagingHosts)".into())
}
#[cfg(not(unix))]
pub fn uninstall() -> Vec<PathBuf> {
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
        let mk = |name: &str, url: &str| LoginEntry { name: name.into(), url: url.into(), username: "u".into(), password: "p".into(), note: String::new(), icon: None, group: String::new() };
        v.passwords.push(mk("GitHub", "https://github.com/login"));
        v.passwords.push(mk("accounts.google.com", ""));
        v.passwords.push(mk("Evil", "https://github.com.evil.io"));
        let mut c = TotpEntry::new("GitHub (b0ris8)", "JBSWY3DPEHPK3PXP");
        c.issuer = "GitHub".into();
        v.codes.push(c);
        v.codes.push(TotpEntry::new("Google (me)", "GEZDGNBVGY3TQOJQ"));
        let r = found(&v, "github.com");
        assert_eq!(r["logins"].as_array().unwrap().len(), 1);
        assert_eq!(r["totp"].as_array().unwrap().len(), 1);
        let r = found(&v, "accounts.google.com");
        assert_eq!(r["logins"].as_array().unwrap().len(), 1);
        assert_eq!(r["logins"][0]["name"], "accounts.google.com");
        assert_eq!(r["totp"].as_array().unwrap().len(), 1);
        let r = found(&v, "gist.github.com");
        assert_eq!(r["logins"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn detect_invocation() {
        assert!(invoked_by_browser(&["/home/u/.mozilla/native-messaging-hosts/pass2fa.json".into(), "pass2fa@b0ris8".into()]));
        assert!(invoked_by_browser(&["chrome-extension://abc/".into()]));
        assert!(!invoked_by_browser(&["import".into(), "x.json".into()]));
    }
}
