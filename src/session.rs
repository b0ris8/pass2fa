//! Общее «разблокировано» для GUI, CLI и браузера (native host) — без фонового демона.
//! Linux: kernel keyring пользователя (@u) с таймаутом — ничего не пишется на диск:
//!   pass2fa:pass  — мастер-пароль (нужен для записи и пересборки кэша);
//!   pass2fa:cache — x25519-ключ быстрого кэша.
//! Кэш: $XDG_RUNTIME_DIR/pass2fa/cache.age (tmpfs, 0600) — то же хранилище, зашифрованное age на
//! случайный ключ из keyring: чтение ~мс вместо ~1 с scrypt на каждый запрос браузера.
//! Ключи @u доступны процессам этого пользователя — граница доверия та же, что у всей сессии.
use crate::model::Vault;
use age::secrecy::SecretString;
use std::path::Path;

/// Сколько держится разблокировка без обращений (каждое обращение продлевает).
pub const TTL_SECS: usize = 30 * 60;

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use age::secrecy::ExposeSecret;
    use linux_keyutils::{KeyRing, KeyRingIdentifier};
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::str::FromStr;

    const K_PASS: &str = "pass2fa:pass";
    const K_CACHE: &str = "pass2fa:cache";

    fn ring() -> Option<KeyRing> {
        KeyRing::from_special_id(KeyRingIdentifier::User, false).ok()
    }

    fn put(desc: &str, secret: &[u8]) -> Result<(), String> {
        let r = ring().ok_or("kernel keyring недоступен")?;
        let k = r.add_key(desc, secret).map_err(|e| format!("keyring: {e:?}"))?;
        k.set_timeout(TTL_SECS).map_err(|e| format!("keyring timeout: {e:?}"))
    }

    fn get(desc: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        let k = ring()?.search(desc).ok()?;
        let v = k.read_to_vec().ok()?;
        let _ = k.set_timeout(TTL_SECS); // использование продлевает
        Some(zeroize::Zeroizing::new(v))
    }

    fn drop_key(desc: &str) {
        if let Some(k) = ring().and_then(|r| r.search(desc).ok()) {
            let _ = k.invalidate();
        }
    }

    fn cache_path() -> Option<PathBuf> {
        let d = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)?;
        Some(d.join("pass2fa").join("cache.age"))
    }

    /// Отпечаток файла хранилища: если его поменял кто-то другой (CLI import), кэш устарел.
    fn stamp(vault: &Path) -> String {
        std::fs::metadata(vault)
            .map(|m| format!("{:?}:{}", m.modified().ok(), m.len()))
            .unwrap_or_default()
    }

    fn write_cache(vault_path: &Path, v: &Vault, id: &age::x25519::Identity) -> Result<(), String> {
        let Some(p) = cache_path() else { return Ok(()) };
        let dir = p.parent().unwrap();
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let payload = zeroize::Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({ "stamp": stamp(vault_path), "vault": v })).map_err(|e| e.to_string())?,
        );
        let rcp = id.to_public();
        let enc = age::Encryptor::with_recipients(std::iter::once(&rcp as &dyn age::Recipient)).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        {
            let mut w = enc.wrap_output(&mut out).map_err(|e| e.to_string())?;
            w.write_all(&payload).map_err(|e| e.to_string())?;
            w.finish().map_err(|e| e.to_string())?;
        }
        let tmp = p.with_extension("tmp");
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
            f.write_all(&out).map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, &p).map_err(|e| e.to_string())
    }

    fn read_cache(vault_path: &Path) -> Option<Vault> {
        let id_raw = get(K_CACHE)?;
        let id = age::x25519::Identity::from_str(std::str::from_utf8(&id_raw).ok()?).ok()?;
        let raw = std::fs::read(cache_path()?).ok()?;
        let dec = age::Decryptor::new(&raw[..]).ok()?;
        let mut r = dec.decrypt(std::iter::once(&id as &dyn age::Identity)).ok()?;
        let mut buf = zeroize::Zeroizing::new(Vec::new());
        r.read_to_end(&mut buf).ok()?;
        let j: serde_json::Value = serde_json::from_slice(&buf).ok()?;
        if j.get("stamp")?.as_str()? != stamp(vault_path) {
            return None;
        }
        serde_json::from_value(j.get("vault")?.clone()).ok()
    }

    pub fn publish(vault_path: &Path, pass: &SecretString, v: &Vault) -> Result<(), String> {
        put(K_PASS, pass.expose_secret().as_bytes())?;
        let id = age::x25519::Identity::generate();
        put(K_CACHE, id.to_string().expose_secret().as_bytes())?;
        write_cache(vault_path, v, &id)
    }

    pub fn refresh_cache(vault_path: &Path, v: &Vault) {
        let Some(raw) = get(K_CACHE) else { return };
        let Some(id) = std::str::from_utf8(&raw).ok().and_then(|s| age::x25519::Identity::from_str(s).ok()) else { return };
        let _ = write_cache(vault_path, v, &id);
    }

    pub fn passphrase() -> Option<SecretString> {
        let raw = get(K_PASS)?;
        Some(SecretString::from(String::from_utf8(raw.to_vec()).ok()?))
    }

    pub fn clear() {
        drop_key(K_PASS);
        drop_key(K_CACHE);
        if let Some(p) = cache_path() {
            let _ = std::fs::remove_file(p);
        }
    }

    /// Разблокированное хранилище: из кэша (быстро) или из файла по паролю из keyring.
    pub fn load(vault_path: &Path) -> Result<Option<Vault>, String> {
        let Some(pass) = passphrase() else { return Ok(None) };
        if let Some(v) = read_cache(vault_path) {
            return Ok(Some(v));
        }
        let v = crate::vault::load(vault_path, &pass)?;
        refresh_cache(vault_path, &v);
        if read_cache(vault_path).is_none() {
            // ключа кэша нет (истёк отдельно) — выпускаем заново
            let _ = publish(vault_path, &pass, &v);
        }
        Ok(Some(v))
    }

    pub fn supported() -> bool {
        ring().is_some()
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    //! TODO Windows: DPAPI. Пока браузерная разблокировка только на Linux.
    use super::*;
    pub fn publish(_: &Path, _: &SecretString, _: &Vault) -> Result<(), String> { Ok(()) }
    pub fn refresh_cache(_: &Path, _: &Vault) {}
    pub fn passphrase() -> Option<SecretString> { None }
    pub fn clear() {}
    pub fn load(_: &Path) -> Result<Option<Vault>, String> { Ok(None) }
    pub fn supported() -> bool { false }
}

pub use imp::*;
