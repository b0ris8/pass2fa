//! Зашифрованный файл хранилища: стандартный формат age (scrypt по паролю), внутри JSON.
//! Восстановление без этого приложения:  age -d vault.age > vault.json
use crate::model::Vault;
use age::secrecy::SecretString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub fn default_path() -> PathBuf {
    if let Some(p) = std::env::var_os("PASS2FA_VAULT") {
        return PathBuf::from(p);
    }
    let mut d = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    d.push("2FApass");
    d.push("vault.age");
    d
}

pub fn exists(path: &Path) -> bool {
    path.is_file()
}

pub fn load(path: &Path, pass: &SecretString) -> Result<Vault, String> {
    let raw = fs::read(path).map_err(|e| format!("чтение {}: {e}", path.display()))?;
    let dec = age::Decryptor::new(&raw[..]).map_err(|e| format!("не age-файл: {e}"))?;
    if !dec.is_scrypt() {
        return Err("файл зашифрован не паролем (ожидался age scrypt)".into());
    }
    let id = age::scrypt::Identity::new(pass.clone());
    let mut r = dec.decrypt(std::iter::once(&id as &dyn age::Identity)).map_err(|e| {
        use age::DecryptError as E;
        match e {
            E::NoMatchingKeys | E::DecryptionFailed | E::KeyDecryptionFailed => {
                "неверный пароль (проверь раскладку)".to_string()
            }
            E::InvalidMac | E::InvalidHeader | E::UnknownFormat => format!("файл повреждён: {e}"),
            E::ExcessiveWork { .. } => format!("{e} — файл создан на более мощной машине"),
            other => format!("ошибка расшифровки: {other}"),
        }
    })?;
    let mut json = zeroize::Zeroizing::new(Vec::new());
    r.read_to_end(&mut json).map_err(|e| e.to_string())?;
    let mut v: Vault = serde_json::from_slice(&json).map_err(|e| format!("JSON внутри: {e}"))?;
    v.version = crate::model::FORMAT_VERSION;
    Ok(v)
}

/// Атомарная запись: tmp рядом -> fsync -> старая версия в .bak -> rename.
pub fn save(path: &Path, pass: &SecretString, v: &Vault) -> Result<(), String> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let json = zeroize::Zeroizing::new(serde_json::to_vec(v).map_err(|e| e.to_string())?);
    let enc = age::Encryptor::with_user_passphrase(pass.clone());
    let mut out = Vec::with_capacity(json.len() + 512);
    {
        let mut w = enc.wrap_output(&mut out).map_err(|e| e.to_string())?;
        w.write_all(&json).map_err(|e| e.to_string())?;
        w.finish().map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("age.tmp");
    {
        let mut f = open_private(&tmp)?;
        f.write_all(&out).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    // контроль: свежезаписанный файл должен расшифроваться
    let check = load(&tmp, pass)?;
    if check.codes.len() != v.codes.len() || check.passwords.len() != v.passwords.len() {
        let _ = fs::remove_file(&tmp);
        return Err("контрольное чтение не совпало, запись отменена".into());
    }
    if path.exists() {
        let _ = fs::copy(path, path.with_extension("age.bak"));
    }
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn open_private(p: &Path) -> Result<fs::File, String> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(p).map_err(|e| format!("{}: {e}", p.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TotpEntry;

    #[test]
    fn change_password_cycle() {
        let dir = std::env::temp_dir().join(format!("pass2fa-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let p = dir.join("vault.age");
        let a = SecretString::from("старый-pass-123".to_string());
        let b = SecretString::from("new-password-456".to_string());
        let mut v = Vault::default();
        v.codes.push(TotpEntry::new("x", "JBSWY3DPEHPK3PXP"));
        save(&p, &a, &v).unwrap();
        save(&p, &b, &v).unwrap();
        assert_eq!(load(&p, &b).unwrap().codes.len(), 1);
        assert!(load(&p, &a).unwrap_err().contains("неверный пароль"));
        assert_eq!(load(&p.with_extension("age.bak"), &a).unwrap().codes.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
