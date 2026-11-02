//! Общее «разблокировано» для GUI, CLI и браузера (native host) — без фонового демона.
//! Linux: kernel keyring пользователя (@u) с таймаутом хранит только КЛЮЧ ХРАНИЛИЩА (не мастер-пароль):
//! с ним vault.age читается/пишется за миллисекунды. На диск ничего не пишется.
//! Ключи @u доступны процессам этого пользователя — граница доверия та же, что у всей сессии.
//! Windows: тот же ключ, обёрнутый DPAPI, в %LOCALAPPDATA%\pass2fa\session.bin (см. imp ниже).
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

#[cfg(windows)]
mod imp {
    //! Windows: ключ хранилища + срок действия, зашифрованные DPAPI (CryptProtectData, ключ — учётная
    //! запись Windows), в %LOCALAPPDATA%\pass2fa\session.bin. Расшифровать может только этот пользователь
    //! на этой машине — та же граница доверия, что у keyring @u на Linux. Срок проверяет программа;
    //! каждое обращение продлевает, истёкший или битый файл стирается.
    use super::*;
    use age::secrecy::ExposeSecret;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::time::{SystemTime, UNIX_EPOCH};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    use zeroize::Zeroizing;

    fn file() -> Option<PathBuf> {
        Some(dirs::data_local_dir()?.join("pass2fa").join("session.bin"))
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    fn dpapi(data: &[u8], protect: bool) -> Option<Zeroizing<Vec<u8>>> {
        let input = CRYPT_INTEGER_BLOB { cbData: u32::try_from(data.len()).ok()?, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let ok = unsafe {
            if protect {
                CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            } else {
                CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            }
        };
        if ok == 0 || out.pbData.is_null() {
            return None;
        }
        let v = unsafe {
            let s = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
            let v = Zeroizing::new(s.to_vec());
            s.fill(0); // открытый текст от DPAPI — затереть до освобождения
            LocalFree(out.pbData as _);
            v
        };
        Some(v)
    }

    /// Записать ключ со сроком now + TTL.
    fn store(id_text: &str) -> Result<(), String> {
        let f = file().ok_or("нет %LOCALAPPDATA%")?;
        let mut plain = Zeroizing::new(Vec::with_capacity(8 + id_text.len()));
        plain.extend_from_slice(&(now() + TTL_SECS as u64).to_le_bytes());
        plain.extend_from_slice(id_text.as_bytes());
        let enc = dpapi(&plain, true).ok_or("DPAPI: CryptProtectData не удался")?;
        if let Some(d) = f.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        let tmp = f.with_extension("tmp");
        std::fs::write(&tmp, &*enc).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &f).map_err(|e| format!("{}: {e}", f.display()))
    }

    pub fn publish(id: &Identity) -> Result<(), String> {
        store(id.to_string().expose_secret())
    }

    pub fn identity() -> Option<Identity> {
        let f = file()?;
        let enc = std::fs::read(&f).ok()?;
        let Some(plain) = dpapi(&enc, false) else {
            clear();
            return None;
        };
        if plain.len() <= 8 {
            clear();
            return None;
        }
        let exp = u64::from_le_bytes(plain[..8].try_into().ok()?);
        if exp <= now() {
            clear();
            return None;
        }
        let text = Zeroizing::new(std::str::from_utf8(&plain[8..]).ok()?.to_string());
        let id = Identity::from_str(&text).ok()?;
        let _ = store(&text); // использование продлевает
        Some(id)
    }

    pub fn clear() {
        if let Some(f) = file() {
            if let Ok(m) = std::fs::metadata(&f) {
                let _ = std::fs::write(&f, vec![0u8; m.len() as usize]);
            }
            let _ = std::fs::remove_file(&f);
        }
    }

    pub fn supported() -> bool {
        true
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod imp {
    //! Прочие ОС: общей разблокировки нет (окно и CLI спрашивают пароль сами, браузер — не работает).
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
