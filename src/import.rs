//! Импорт: старый JSON (store.json / otp_data.json), CSV (Chrome/Firefox, Proton Pass, Bitwarden),
//! текст со строками otpauth://.
use crate::model::{LoginEntry, TotpEntry, Vault};
use crate::totp;
use std::collections::HashMap;
use std::path::Path;

pub fn from_file(path: &Path) -> Result<Vault, String> {
    let raw = zeroize::Zeroizing::new(
        std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?,
    );
    let t = raw.trim_start_matches('\u{feff}').trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        let val: serde_json::Value = serde_json::from_str(t).map_err(|e| format!("JSON: {e}"))?;
        let own = val.get("codes").is_some() || val.get("passwords").is_some() || val.get("logins").is_some();
        let mut v = if own {
            serde_json::from_value::<Vault>(val).map_err(|e| format!("JSON: {e}"))?
        } else {
            foreign_json(&val)?
        };
        // относительные пути иконок — относительно папки файла импорта
        let base = path.parent().unwrap_or(Path::new("."));
        for c in v.codes.iter_mut() {
            if let Some(p) = &c.icon_path {
                let pb = Path::new(p);
                if pb.is_relative() {
                    c.icon_path = Some(base.join(pb).to_string_lossy().into_owned());
                }
            }
        }
        if v.codes.is_empty() && v.passwords.is_empty() {
            return Err("в файле не найдено ни одной записи".into());
        }
        return Ok(v);
    }
    if t.starts_with("otpauth://") {
        let mut v = Vault::default();
        for line in t.lines().filter(|l| l.trim().starts_with("otpauth://")) {
            v.codes.push(totp::parse_otpauth(line).ok_or_else(|| format!("не разобрал: {}", mask(line)))?);
        }
        return Ok(v);
    }
    from_csv(t)
}

/// Чужой JSON: Aegis (plaintext), Proton Authenticator, 2FAS и т.п. Ищем рекурсивно
/// строки otpauth:// и объекты с полем secret (имя/issuer берём из объекта или родителя).
fn foreign_json(val: &serde_json::Value) -> Result<Vault, String> {
    use serde_json::Value;
    // зашифрованные экспорты
    if let Some(h) = val.get("header") {
        if !h.get("slots").map(Value::is_null).unwrap_or(true) || val.get("db").map(Value::is_string).unwrap_or(false) {
            return Err("экспорт Aegis зашифрован — сделай экспорт без шифрования".into());
        }
    }
    fn s<'a>(o: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
        keys.iter().find_map(|k| o.get(*k).and_then(Value::as_str)).filter(|x| !x.trim().is_empty())
    }
    fn n(o: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u64> {
        keys.iter().find_map(|k| o.get(*k).and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok())))
    }
    fn walk(v: &Value, name: Option<&str>, issuer: Option<&str>, out: &mut Vec<TotpEntry>) {
        match v {
            Value::String(x) if x.trim_start().starts_with("otpauth://") => {
                if let Some(mut e) = totp::parse_otpauth(x) {
                    if e.name.is_empty() { e.name = name.unwrap_or("").to_string(); }
                    out.push(e);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, name, issuer, out)),
            Value::Object(o) => {
                let my_name = s(o, &["name", "label", "account", "title"]).or(name);
                let my_issuer = s(o, &["issuer", "service"]).or(issuer);
                let has_uri = o.values().any(|x| x.as_str().is_some_and(|t| t.trim_start().starts_with("otpauth://")));
                let ty = s(o, &["type", "otp_type", "entry_type"]).unwrap_or("totp").to_lowercase();
                if let (Some(sec), false) = (s(o, &["secret"]), has_uri) {
                    if (ty.contains("totp") || ty == "steam") && totp::base32_decode(sec).is_some() {
                        let nm = match (my_issuer, my_name) {
                            (Some(i), Some(a)) if i != a => format!("{i} ({a})"),
                            (Some(i), _) => i.to_string(),
                            (None, Some(a)) => a.to_string(),
                            _ => "без имени".to_string(),
                        };
                        let mut e = TotpEntry::new(&nm, &sec.to_uppercase());
                        e.issuer = my_issuer.unwrap_or("").to_string();
                        e.digits = n(o, &["digits"]).unwrap_or(6) as u32;
                        e.period = n(o, &["period", "interval"]).unwrap_or(30);
                        e.algorithm = match s(o, &["algo", "algorithm"]).unwrap_or("SHA1").to_uppercase().replace('-', "").as_str() {
                            "SHA256" => crate::model::Algo::SHA256,
                            "SHA512" => crate::model::Algo::SHA512,
                            _ => crate::model::Algo::SHA1,
                        };
                        out.push(e);
                        return;
                    }
                }
                for x in o.values() { walk(x, my_name, my_issuer, out); }
            }
            _ => {}
        }
    }
    let mut v = Vault::default();
    // PassVault: массив объектов {title, username, password, email, url, notes, customFields, type}
    if let Some(arr) = val.as_array() {
        for o in arr.iter().filter_map(Value::as_object) {
            let (Some(title), Some(pw)) = (o.get("title").and_then(Value::as_str), o.get("password").and_then(Value::as_str)) else { continue };
            let g = |k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").trim().to_string();
            let mut username = g("username");
            if username.is_empty() { username = g("email"); }
            v.passwords.push(LoginEntry {
                name: title.trim().to_string(),
                url: g("url"),
                username,
                password: pw.to_string(),
                note: g("notes"),
                icon: None,
            });
        }
    }
    let mut codes = Vec::new();
    walk(val, None, None, &mut codes);
    let mut seen = std::collections::HashSet::new();
    for c in codes.iter() {
        let key: String = c.secret.chars().filter(|ch| ch.is_ascii_alphanumeric()).collect::<String>().to_uppercase();
        if seen.insert(key) { v.codes.push(c.clone()); }
    }
    if v.codes.is_empty() && v.passwords.is_empty() {
        return Err("не нашёл ни 2FA, ни паролей (ни otpauth://, ни полей secret). Если экспорт зашифрован — выгрузи без шифрования".into());
    }
    Ok(v)
}

fn mask(s: &str) -> String {
    s.split("secret=").next().unwrap_or("").to_string() + "secret=…"
}

fn from_csv(text: &str) -> Result<Vault, String> {
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(text.as_bytes());
    let hdr: Vec<String> = rdr
        .headers()
        .map_err(|e| format!("CSV: {e}"))?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let idx: HashMap<&str, usize> = hdr.iter().enumerate().map(|(i, h)| (h.as_str(), i)).collect();
    let col = |names: &[&str]| names.iter().find_map(|n| idx.get(n).copied());
    let c_name = col(&["name", "title"]);
    let c_url = col(&["url", "login_uri", "website"]);
    let c_user = col(&["username", "login_username", "login"]);
    let c_email = col(&["email"]);
    let c_pass = col(&["password", "login_password"]);
    let c_note = col(&["note", "notes", "extra"]);
    let c_totp = col(&["totp", "login_totp", "otp", "otpauth"]);
    let c_type = col(&["type"]);
    if c_pass.is_none() && c_totp.is_none() {
        return Err(format!("CSV: не нашёл колонок password/totp, заголовок: {:?}", hdr));
    }
    let mut v = Vault::default();
    for (n, rec) in rdr.records().enumerate() {
        let rec = rec.map_err(|e| format!("CSV строка {}: {e}", n + 2))?;
        let get = |c: Option<usize>| c.and_then(|i| rec.get(i)).unwrap_or("").trim().to_string();
        // Proton Pass: type = login | note | alias | creditCard ... ; берём только login
        let ty = get(c_type).to_lowercase();
        if !ty.is_empty() && ty != "login" {
            continue;
        }
        let mut name = get(c_name);
        let url = get(c_url);
        let mut username = get(c_user);
        if username.is_empty() {
            username = get(c_email);
        }
        if name.is_empty() {
            name = if url.is_empty() { username.clone() } else { url.clone() };
        }
        let password = get(c_pass);
        let note = get(c_note);
        let otp = get(c_totp);
        if !password.is_empty() || !username.is_empty() {
            v.passwords.push(LoginEntry { name: name.clone(), url, username: username.clone(), password, note, icon: None });
        }
        if !otp.is_empty() {
            let e = if otp.starts_with("otpauth://") {
                totp::parse_otpauth(&otp)
            } else {
                totp::base32_decode(&otp).map(|_| TotpEntry::new(&name, &otp.to_uppercase()))
            };
            match e {
                Some(mut e) => {
                    if e.name.is_empty() { e.name = name.clone(); }
                    v.codes.push(e)
                }
                None => return Err(format!("CSV строка {}: не разобрал TOTP для «{}»", n + 2, name)),
            }
        }
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aegis_roundtrip() {
        let mut v = Vault::default();
        let mut e = TotpEntry::new("GitHub (me)", "JBSWY3DPEHPK3PXP");
        e.issuer = "GitHub".into();
        v.codes.push(e);
        let j = crate::export::aegis_json(&v);
        assert_eq!(j["db"]["entries"][0]["issuer"], "GitHub");
        assert_eq!(j["db"]["entries"][0]["name"], "me");
        let back = foreign_json(&j).unwrap();
        assert_eq!(back.codes.len(), 1);
        assert_eq!(back.codes[0].name, "GitHub (me)");
        assert_eq!(back.codes[0].secret, "JBSWY3DPEHPK3PXP");
    }
    #[test]
    fn proton_authenticator_like() {
        // две вероятные формы: uri внутри content и плоский secret
        let j: serde_json::Value = serde_json::from_str(r#"{"version":1,"entries":[
            {"id":"1","content":{"uri":"otpauth://totp/Proton:me?secret=JBSWY3DPEHPK3PXP&issuer=Proton","entry_type":"Totp","name":"me"},"note":null},
            {"id":"2","name":"Bank","issuer":"MyBank","secret":"GEZDGNBVGY3TQOJQ","period":30,"digits":6,"algorithm":"SHA1"}]}"#).unwrap();
        let v = foreign_json(&j).unwrap();
        assert_eq!(v.codes.len(), 2);
        assert_eq!(v.codes[1].name, "MyBank (Bank)");
    }
    #[test]
    fn encrypted_aegis_rejected() {
        let j: serde_json::Value = serde_json::from_str(r#"{"version":1,"header":{"slots":[{}],"params":{}},"db":"base64..."}"#).unwrap();
        assert!(foreign_json(&j).is_err());
    }
    #[test]
    fn passvault_roundtrip() {
        let mut v = Vault::default();
        v.passwords.push(LoginEntry { name: "GitHub".into(), url: "https://github.com".into(), username: "b0ris8".into(), password: "p@ss".into(), note: "n".into(), icon: None });
        v.passwords.push(LoginEntry { name: "Заметка".into(), url: String::new(), username: String::new(), password: String::new(), note: "текст".into(), icon: None });
        let j = crate::export::passvault_json(&v);
        // ровно поля ImportRecord, nullable — явно
        let keys: Vec<_> = j[0].as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys.len(), 11);
        assert!(j[1]["username"].is_null());
        assert_eq!(j[1]["type"], "NOTE");
        let back = foreign_json(&j).unwrap();
        assert_eq!(back.passwords.len(), 2);
        assert_eq!(back.passwords[0].password, "p@ss");
        assert_eq!(back.passwords[0].username, "b0ris8");
    }
    #[test]
    fn passvault_customfield_totp() {
        let j: serde_json::Value = serde_json::from_str(r#"[{"title":"Site","username":null,"password":"x","email":"me@x.md","url":null,"category":"General","notes":null,"createdAt":1,"updatedAt":1,
            "customFields":[{"id":"1","name":"2fa","value":"otpauth://totp/Site:me?secret=JBSWY3DPEHPK3PXP","isSecret":true,"meta":{},"order":0}],"type":"PASSWORD"}]"#).unwrap();
        let v = foreign_json(&j).unwrap();
        assert_eq!(v.passwords[0].username, "me@x.md");
        assert_eq!(v.codes.len(), 1);
    }
    #[test]
    fn chrome_csv() {
        let v = from_csv("name,url,username,password,note\nsite,https://a.b,u,p,\n").unwrap();
        assert_eq!(v.passwords.len(), 1);
        assert_eq!(v.passwords[0].password, "p");
    }
    #[test]
    fn proton_csv() {
        let s = "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n\
                 login,GitHub,https://github.com,me@x.md,,pw,,otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub,1,2,Personal\n\
                 note,Secret note,,,,,text,,1,2,Personal\n";
        let v = from_csv(s).unwrap();
        assert_eq!(v.passwords.len(), 1);
        assert_eq!(v.passwords[0].username, "me@x.md");
        assert_eq!(v.codes.len(), 1);
    }
}
