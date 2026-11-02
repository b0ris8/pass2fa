//! Хранилище — два файла стандартного формата age (как «ключ, обёрнутый паролем» в KeePass):
//!   vault.key.age — случайный ключ хранилища (age X25519), зашифрованный мастер-паролем (scrypt, ~1 c);
//!   vault.age     — данные (JSON), зашифрованные этим ключом: сохранение — миллисекунды.
//! Медленный scrypt — только при входе и смене пароля. Подбор пароля так же дорог, как раньше.
//! Восстановление без программы:  age -d -i vault.key.age vault.age > vault.json   (age спросит пароль)
//! ДЛЯ БЭКАПА НУЖНЫ ОБА ФАЙЛА. Старый формат (vault.age по паролю) открывается и мигрирует автоматически.
use crate::model::Vault;
use age::secrecy::{ExposeSecret, SecretString};
use age::x25519::Identity;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub fn default_path() -> PathBuf {
    if let Some(p) = std::env::var_os("PASS2FA_VAULT") {
        return PathBuf::from(p);
    }
    let mut d = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    d.push("2FApass");
    d.push("vault.age");
    d
}

/// vault.age → vault.key.age
pub fn key_path(vault: &Path) -> PathBuf {
    vault.with_extension("key.age")
}

pub fn exists(path: &Path) -> bool {
    path.is_file()
}

fn decrypt_err(e: age::DecryptError) -> String {
    use age::DecryptError as E;
    match e {
        E::NoMatchingKeys | E::DecryptionFailed | E::KeyDecryptionFailed => "неверный пароль (проверь раскладку)".to_string(),
        E::InvalidMac | E::InvalidHeader | E::UnknownFormat => format!("файл повреждён: {e}"),
        E::ExcessiveWork { .. } => format!("{e} — файл создан на более мощной машине"),
        other => format!("ошибка расшифровки: {other}"),
    }
}

fn decrypt(raw: &[u8], id: &dyn age::Identity) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let dec = age::Decryptor::new(raw).map_err(|e| format!("не age-файл: {e}"))?;
    let mut r = dec.decrypt(std::iter::once(id)).map_err(decrypt_err)?;
    let mut out = zeroize::Zeroizing::new(Vec::new());
    r.read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn encrypt(data: &[u8], rcp: &dyn age::Recipient) -> Result<Vec<u8>, String> {
    let enc = age::Encryptor::with_recipients(std::iter::once(rcp)).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(data.len() + 512);
    let mut w = enc.wrap_output(&mut out).map_err(|e| e.to_string())?;
    w.write_all(data).map_err(|e| e.to_string())?;
    w.finish().map_err(|e| e.to_string())?;
    Ok(out)
}

fn parse_vault(json: &[u8]) -> Result<Vault, String> {
    let mut v: Vault = serde_json::from_slice(json).map_err(|e| format!("JSON внутри: {e}"))?;
    v.version = crate::model::FORMAT_VERSION;
    Ok(v)
}

fn is_scrypt_file(raw: &[u8]) -> bool {
    age::Decryptor::new(raw).map(|d| d.is_scrypt()).unwrap_or(false)
}

/// Старый формат: vault.age целиком по паролю (scrypt).
pub fn load_legacy(path: &Path, pass: &SecretString) -> Result<Vault, String> {
    let raw = fs::read(path).map_err(|e| format!("чтение {}: {e}", path.display()))?;
    if !is_scrypt_file(&raw) {
        return Err("файл зашифрован не паролем".into());
    }
    parse_vault(&decrypt(&raw, &age::scrypt::Identity::new(pass.clone()))?)
}

/// Ключ хранилища из vault.key.age по паролю (медленно — scrypt).
pub fn unwrap_key(vault: &Path, pass: &SecretString) -> Result<Identity, String> {
    let kp = key_path(vault);
    let raw = fs::read(&kp).map_err(|e| format!("чтение {}: {e}", kp.display()))?;
    let txt = decrypt(&raw, &age::scrypt::Identity::new(pass.clone()))?;
    let s = std::str::from_utf8(&txt).map_err(|_| "ключ повреждён".to_string())?;
    // файл в формате age-keygen: комментарии + строка AGE-SECRET-KEY-…
    let line = s.lines().map(str::trim).find(|l| l.starts_with("AGE-SECRET-KEY-")).ok_or("в файле ключа нет AGE-SECRET-KEY")?;
    Identity::from_str(line).map_err(|e| format!("ключ повреждён: {e}"))
}

/// Записать ключ хранилища, обёрнутый паролем (формат age-keygen, читается `age -d -i`).
fn wrap_key(vault: &Path, id: &Identity, pass: &SecretString) -> Result<(), String> {
    let body = zeroize::Zeroizing::new(format!(
        "# pass2fa: ключ хранилища {}\n# public key: {}\n{}\n",
        vault.file_name().and_then(|n| n.to_str()).unwrap_or("vault.age"),
        id.to_public(),
        id.to_string().expose_secret()
    ));
    let out = encrypt(body.as_bytes(), &age::scrypt::Recipient::new(pass.clone()))?;
    atomic_write(&key_path(vault), &out)?;
    // контроль: ключ разворачивается тем же паролем
    match unwrap_key(vault, pass) {
        Ok(back) if back.to_public().to_string() == id.to_public().to_string() => Ok(()),
        _ => Err("контрольное чтение ключа не совпало".into()),
    }
}

/// Быстро: данные по уже развёрнутому ключу.
pub fn load_with(path: &Path, id: &Identity) -> Result<Vault, String> {
    let raw = fs::read(path).map_err(|e| format!("чтение {}: {e}", path.display()))?;
    let dec = age::Decryptor::new(&raw[..]).map_err(|e| format!("не age-файл: {e}"))?;
    let mut r = dec.decrypt(std::iter::once(id as &dyn age::Identity)).map_err(|e| match e {
        // пароль тут не участвует: ключ уже развёрнут, значит vault.age зашифрован другим ключом
        age::DecryptError::NoMatchingKeys => format!(
            "{} не от этого ключа: vault.age и vault.key.age из разных копий (скопируй оба файла вместе)",
            path.display()
        ),
        other => decrypt_err(other),
    })?;
    let mut out = zeroize::Zeroizing::new(Vec::new());
    r.read_to_end(&mut out).map_err(|e| e.to_string())?;
    parse_vault(&out)
}

/// Вход по паролю: новый формат — развернуть ключ; старый — прочитать и мигрировать.
pub fn unlock(path: &Path, pass: &SecretString) -> Result<(Vault, Identity), String> {
    if key_path(path).exists() {
        let id = unwrap_key(path, pass)?;
        let v = load_with(path, &id)?;
        return Ok((v, id));
    }
    let v = load_legacy(path, pass)?;
    let _ = fs::copy(path, path.with_extension("age.legacy"));
    let id = Identity::generate();
    wrap_key(path, &id, pass)?;
    save(path, &id, &v)?;
    Ok((v, id))
}

/// Новое хранилище: ключ + пустые данные.
pub fn create(path: &Path, pass: &SecretString, v: &Vault) -> Result<Identity, String> {
    let id = Identity::generate();
    if let Some(d) = path.parent() {
        fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    wrap_key(path, &id, pass)?;
    save(path, &id, v)?;
    Ok(id)
}

/// Смена пароля: перешифровать только ключ (данные не трогаем). Старый ключ-файл — в копию.
pub fn change_password(path: &Path, old: &SecretString, new: &SecretString) -> Result<PathBuf, String> {
    let id = unwrap_key(path, old)?; // проверяет текущий пароль
    let keep = key_path(path).with_extension(format!("age.before-passwd-{}", crate::totp::now()));
    fs::copy(key_path(path), &keep).map_err(|e| e.to_string())?;
    wrap_key(path, &id, new)?;
    Ok(keep)
}

/// Атомарная запись данных: tmp → fsync → контрольное чтение → старая версия в .bak → rename.
pub fn save(path: &Path, id: &Identity, v: &Vault) -> Result<(), String> {
    let json = zeroize::Zeroizing::new(serde_json::to_vec(v).map_err(|e| e.to_string())?);
    let out = encrypt(&json, &id.to_public())?;
    let tmp = path.with_extension("age.tmp");
    {
        let mut f = open_private(&tmp)?;
        f.write_all(&out).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    let check = load_with(&tmp, id)?;
    if check.codes.len() != v.codes.len() || check.passwords.len() != v.passwords.len() {
        let _ = fs::remove_file(&tmp);
        return Err("контрольное чтение не совпало, запись отменена".into());
    }
    if path.exists() {
        let _ = fs::copy(path, path.with_extension("age.bak"));
    }
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn atomic_write(p: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(d, fs::Permissions::from_mode(0o700));
        }
    }
    let tmp = p.with_extension("tmp");
    {
        let mut f = open_private(&tmp)?;
        f.write_all(data).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp, p).map_err(|e| e.to_string())
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

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pass2fa-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn sample() -> Vault {
        let mut v = Vault::default();
        v.codes.push(TotpEntry::new("x", "JBSWY3DPEHPK3PXP"));
        v
    }

    #[test]
    fn create_save_fast_and_change_password() {
        let d = tmpdir("new");
        let p = d.join("vault.age");
        let a = SecretString::from("старый-pass-123".to_string());
        let b = SecretString::from("new-password-456".to_string());
        let id = create(&p, &a, &sample()).unwrap();
        // сохранение без scrypt — быстро
        let t = std::time::Instant::now();
        for _ in 0..5 { save(&p, &id, &sample()).unwrap(); }
        assert!(t.elapsed().as_millis() < 500, "5 сохранений заняли {:?}", t.elapsed());
        assert_eq!(unlock(&p, &a).unwrap().0.codes.len(), 1);
        let keep = change_password(&p, &a, &b).unwrap();
        assert!(keep.exists());
        assert!(unlock(&p, &a).err().unwrap().contains("неверный пароль"));
        assert_eq!(unlock(&p, &b).unwrap().0.codes.len(), 1);
        assert!(change_password(&p, &a, &b).is_err()); // неверный текущий
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn migrate_legacy() {
        let d = tmpdir("legacy");
        let p = d.join("vault.age");
        let pass = SecretString::from("legacy-pass-123".to_string());
        // старый формат: весь файл по паролю
        let json = serde_json::to_vec(&sample()).unwrap();
        fs::write(&p, encrypt(&json, &age::scrypt::Recipient::new(pass.clone())).unwrap()).unwrap();
        assert!(!key_path(&p).exists());
        let (v, id) = unlock(&p, &pass).unwrap();
        assert_eq!(v.codes.len(), 1);
        assert!(key_path(&p).exists());
        assert!(p.with_extension("age.legacy").exists());
        assert!(!is_scrypt_file(&fs::read(&p).unwrap())); // данные теперь на ключе
        assert_eq!(load_with(&p, &id).unwrap().codes.len(), 1);
        assert_eq!(unlock(&p, &pass).unwrap().0.codes.len(), 1); // повторный вход — новый формат
        let _ = fs::remove_dir_all(&d);
    }
}
