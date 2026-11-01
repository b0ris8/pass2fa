//! Экспорт 2FA в открытый (plaintext) формат хранилища Aegis: vault format v1, db v3.
//! Файл содержит секреты в открытом виде — только для разового переноса, потом удалить.
use crate::model::{Algo, Vault};
use serde_json::json;
use std::io::Write;
use std::path::Path;

fn uuid4() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("системный RNG недоступен");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

pub fn aegis_json(v: &Vault) -> serde_json::Value {
    let entries: Vec<_> = v
        .codes
        .iter()
        .map(|c| {
            // в pass2fa name вида «Issuer (account)» — для Aegis разделяем обратно
            let (issuer, name) = if !c.issuer.is_empty() {
                let acc = c
                    .name
                    .strip_prefix(&format!("{} (", c.issuer))
                    .and_then(|s| s.strip_suffix(')'))
                    .unwrap_or(&c.name);
                (c.issuer.clone(), acc.to_string())
            } else {
                (c.name.clone(), String::new())
            };
            json!({
                "type": "totp",
                "uuid": uuid4(),
                "name": name,
                "issuer": issuer,
                "note": "",
                "favorite": false,
                "icon": null,
                "icon_mime": null,
                "icon_hash": null,
                "info": {
                    "secret": c.secret.chars().filter(|ch| !ch.is_whitespace() && *ch != '=').collect::<String>().to_uppercase(),
                    "algo": match c.algorithm { Algo::SHA1 => "SHA1", Algo::SHA256 => "SHA256", Algo::SHA512 => "SHA512" },
                    "digits": c.digits,
                    "period": c.period
                },
                "groups": []
            })
        })
        .collect();
    json!({
        "version": 1,
        "header": { "slots": null, "params": null },
        "db": { "version": 3, "entries": entries, "groups": [] }
    })
}

/// PassVault (Android, com.jksalcedo.passvault): JSON-экспорт = массив ImportRecord.
/// Его парсер строгий (kotlinx.serialization по умолчанию): только эти поля, nullable — явно.
pub fn passvault_json(v: &Vault) -> serde_json::Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let opt = |s: &str| if s.is_empty() { serde_json::Value::Null } else { json!(s) };
    serde_json::Value::Array(
        v.passwords
            .iter()
            .map(|l| {
                let note_only = l.password.is_empty() && l.username.is_empty() && l.url.is_empty();
                json!({
                    "title": if l.name.is_empty() { "Untitled" } else { l.name.as_str() },
                    "username": opt(&l.username),
                    "password": l.password,
                    "email": null,
                    "url": opt(&l.url),
                    "category": "General",
                    "notes": opt(&l.note),
                    "createdAt": now,
                    "updatedAt": now,
                    "customFields": [],
                    "type": if note_only { "NOTE" } else { "PASSWORD" }
                })
            })
            .collect(),
    )
}

pub fn passvault_to_file(v: &Vault, path: &Path) -> Result<usize, String> {
    write_private(path, &passvault_json(v))?;
    Ok(v.passwords.len())
}

fn write_private(path: &Path, val: &serde_json::Value) -> Result<(), String> {
    let s = zeroize::Zeroizing::new(serde_json::to_string_pretty(val).map_err(|e| e.to_string())?);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(s.as_bytes()).map_err(|e| e.to_string())
}

pub fn aegis_to_file(v: &Vault, path: &Path) -> Result<usize, String> {
    write_private(path, &aegis_json(v))?;
    Ok(v.codes.len())
}
