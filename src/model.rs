//! Модель данных хранилища. Сериализуется в JSON и шифруется целиком (см. vault.rs).
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const FORMAT_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum Algo {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

fn d_digits() -> u32 { 6 }
fn d_period() -> u64 { 30 }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct TotpEntry {
    pub name: String,
    #[serde(default)]
    pub issuer: String,
    /// base32, как выдают сервисы
    pub secret: String,
    #[serde(default = "d_digits")]
    pub digits: u32,
    #[serde(default = "d_period")]
    pub period: u64,
    #[serde(default)]
    #[zeroize(skip)]
    pub algorithm: Algo,
    /// своя иконка: путь к файлу (абсолютный или от папки хранилища) или "si:<slug>"; None — автоподбор
    #[serde(default)]
    pub icon_path: Option<String>,
}

impl TotpEntry {
    pub fn new(name: &str, secret: &str) -> Self {
        Self {
            name: name.into(),
            issuer: String::new(),
            secret: secret.into(),
            digits: 6,
            period: 30,
            algorithm: Algo::SHA1,
            icon_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default, Zeroize, ZeroizeOnDrop)]
pub struct LoginEntry {
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub note: String,
    /// своя иконка: путь к файлу или "si:<slug>" из Simple Icons; None — автоподбор
    #[serde(default)]
    pub icon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Vault {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub codes: Vec<TotpEntry>,
    /// `passwords` — имя поля из старого store.json, оставлено для совместимости
    #[serde(default, alias = "logins")]
    pub passwords: Vec<LoginEntry>,
}

impl Default for Vault {
    fn default() -> Self {
        Self { version: FORMAT_VERSION, codes: vec![], passwords: vec![] }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MergeStats {
    pub codes_added: usize,
    pub codes_updated: usize,
    pub logins_added: usize,
    pub logins_updated: usize,
}

impl std::fmt::Display for MergeStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "2FA: +{} / обновлено {}; пароли: +{} / обновлено {}",
            self.codes_added, self.codes_updated, self.logins_added, self.logins_updated
        )
    }
}

fn norm_secret(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace() && *c != '=').collect::<String>().to_uppercase()
}

impl Vault {
    /// Слияние: 2FA совпадает по секрету, логин — по (name, url, username). Совпавшие обновляются.
    pub fn merge(&mut self, other: Vault) -> MergeStats {
        let mut st = MergeStats::default();
        for c in other.codes.iter() {
            let key = norm_secret(&c.secret);
            if let Some(e) = self.codes.iter_mut().find(|e| norm_secret(&e.secret) == key) {
                if e != c { *e = c.clone(); st.codes_updated += 1; }
            } else {
                self.codes.push(c.clone());
                st.codes_added += 1;
            }
        }
        for l in other.passwords.iter() {
            if let Some(e) = self.passwords.iter_mut().find(|e| {
                e.name == l.name && e.url == l.url && e.username == l.username
            }) {
                if e != l { *e = l.clone(); st.logins_updated += 1; }
            } else {
                self.passwords.push(l.clone());
                st.logins_added += 1;
            }
        }
        self.sort();
        st
    }

    pub fn sort(&mut self) {
        self.codes.sort_by_key(|c| c.name.to_lowercase());
        self.passwords.sort_by_key(|l| l.name.to_lowercase());
    }
}
