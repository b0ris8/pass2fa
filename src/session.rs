//! Общее «разблокировано» для GUI, CLI и браузера (native host) — без фонового демона.
//! Linux: kernel keyring пользователя (@u) с таймаутом хранит только КЛЮЧ ХРАНИЛИЩА (не мастер-пароль):
//! с ним vault.age читается/пишется за миллисекунды. На диск ничего не пишется.
//! Ключи @u доступны процессам этого пользователя — граница доверия та же, что у всей сессии.
use crate::model::Vault;
use age::x25519::Identity;
use std::path::Path;

/// Сколько держится разблокировка без обращений (каждое обращение продлевает).
pub const TTL_SECS: usize = 30 * 60;

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use age::secrecy::ExposeSecret;
    use linux_keyutils::{KeyRing, KeyRingIdentifier};
    use std::str::FromStr;

    const K_ID: &str = "pass2fa:vault-key";
    // ключи прошлой версии — убираем при блокировке
    const LEGACY: [&str; 2] = ["pass2fa:pass", "pass2fa:cache"];

    fn ring() -> Option<KeyRing> {
        KeyRing::from_special_id(KeyRingIdentifier::User, false).ok()
    }

    fn drop_key(desc: &str) {
        if let Some(k) = ring().and_then(|r| r.search(desc).ok()) {
            let _ = k.invalidate();
        }
    }

    pub fn publish(id: &Identity) -> Result<(), String> {
        let r = ring().ok_or("kernel keyring недоступен")?;
        let k = r.add_key(K_ID, id.to_string().expose_secret().as_bytes()).map_err(|e| format!("keyring: {e:?}"))?;
        k.set_timeout(TTL_SECS).map_err(|e| format!("keyring timeout: {e:?}"))
    }

    pub fn identity() -> Option<Identity> {
        let k = ring()?.search(K_ID).ok()?;
        let raw = zeroize::Zeroizing::new(k.read_to_vec().ok()?);
        let _ = k.set_timeout(TTL_SECS); // использование продлевает
        Identity::from_str(std::str::from_utf8(&raw).ok()?).ok()
    }

    pub fn clear() {
        drop_key(K_ID);
        for k in LEGACY {
            drop_key(k);
        }
        // кэш прошлой версии, если остался
        if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
            let _ = std::fs::remove_dir_all(std::path::PathBuf::from(d).join("pass2fa"));
        }
    }

    pub fn supported() -> bool {
        ring().is_some()
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    //! TODO Windows: DPAPI. Пока общая разблокировка только на Linux.
    use super::*;
    pub fn publish(_: &Identity) -> Result<(), String> { Ok(()) }
    pub fn identity() -> Option<Identity> { None }
    pub fn clear() {}
    pub fn supported() -> bool { false }
}

pub use imp::*;

pub fn is_unlocked() -> bool {
    identity().is_some()
}

/// Разблокированное хранилище по ключу из keyring (миллисекунды).
pub fn load(vault_path: &Path) -> Result<Option<(Vault, Identity)>, String> {
    let Some(id) = identity() else { return Ok(None) };
    let v = crate::vault::load_with(vault_path, &id)?;
    Ok(Some((v, id)))
}
