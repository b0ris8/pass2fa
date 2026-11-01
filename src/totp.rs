//! RFC 4226 / RFC 6238. HMAC — из RustCrypto (hmac + sha1/sha2) вместо самописного SHA-1.
use crate::model::{Algo, TotpEntry};
use hmac::{Hmac, Mac};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn base32_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in input.chars() {
        if c.is_whitespace() || c == '=' || c == '-' {
            continue;
        }
        let c = c.to_ascii_uppercase() as u8;
        let v = ALPHA.iter().position(|&b| b == c)? as u64;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn hmac_digest(algo: Algo, key: &[u8], msg: &[u8]) -> Vec<u8> {
    macro_rules! run {
        ($h:ty) => {{
            let mut m = <Hmac<$h> as Mac>::new_from_slice(key).expect("HMAC принимает ключ любой длины");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }};
    }
    match algo {
        Algo::SHA1 => run!(sha1::Sha1),
        Algo::SHA256 => run!(sha2::Sha256),
        Algo::SHA512 => run!(sha2::Sha512),
    }
}

pub fn hotp(algo: Algo, key: &[u8], counter: u64, digits: u32) -> u32 {
    let h = hmac_digest(algo, key, &counter.to_be_bytes());
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = ((h[off] as u32 & 0x7f) << 24)
        | ((h[off + 1] as u32) << 16)
        | ((h[off + 2] as u32) << 8)
        | (h[off + 3] as u32);
    bin % 10u32.pow(digits.clamp(6, 9))
}

/// Код и сколько секунд он ещё действует.
pub fn code_at(e: &TotpEntry, t: u64) -> Option<(String, u64)> {
    let key = base32_decode(&e.secret)?;
    let period = e.period.max(1);
    let digits = e.digits.clamp(6, 9);
    let c = hotp(e.algorithm, &key, t / period, digits);
    Some((format!("{:0width$}", c, width = digits as usize), period - t % period))
}

pub fn code(e: &TotpEntry) -> Option<(String, u64)> {
    code_at(e, now())
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// otpauth://totp/Issuer:account?secret=...&issuer=...&digits=6&period=30&algorithm=SHA1
pub fn parse_otpauth(uri: &str) -> Option<TotpEntry> {
    let rest = uri.trim().strip_prefix("otpauth://")?;
    let (kind, rest) = rest.split_once('/')?;
    if !kind.eq_ignore_ascii_case("totp") {
        return None; // HOTP (счётчик) не поддерживаем
    }
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = pct_decode(label);
    let mut e = TotpEntry::new(&label, "");
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };
    e.issuer = label_issuer;
    for kv in query.split('&') {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let v = pct_decode(v);
        match k.to_ascii_lowercase().as_str() {
            "secret" => e.secret = v.to_uppercase(),
            "issuer" => e.issuer = v,
            "digits" => e.digits = v.parse().unwrap_or(6),
            "period" => e.period = v.parse().unwrap_or(30),
            "algorithm" => {
                e.algorithm = match v.to_ascii_uppercase().as_str() {
                    "SHA256" => Algo::SHA256,
                    "SHA512" => Algo::SHA512,
                    _ => Algo::SHA1,
                }
            }
            _ => {}
        }
    }
    e.name = if e.issuer.is_empty() || account.is_empty() {
        if account.is_empty() { e.issuer.clone() } else { account }
    } else {
        format!("{} ({})", e.issuer, account)
    };
    base32_decode(&e.secret)?;
    Some(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Тестовые векторы RFC 6238, приложение B
    fn ent(algo: Algo, ascii_key: &[u8]) -> TotpEntry {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut s = String::new();
        let (mut buf, mut bits) = (0u32, 0);
        for &b in ascii_key {
            buf = (buf << 8) | b as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                s.push(A[((buf >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 { s.push(A[((buf << (5 - bits)) & 31) as usize] as char); }
        let mut e = TotpEntry::new("t", &s);
        e.digits = 8;
        e.algorithm = algo;
        e
    }

    #[test]
    fn rfc6238() {
        let k1 = b"12345678901234567890".to_vec();
        let k256 = b"12345678901234567890123456789012".to_vec();
        let k512 = b"1234567890123456789012345678901234567890123456789012345678901234".to_vec();
        let cases: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for &(t, s1, s256, s512) in cases {
            assert_eq!(code_at(&ent(Algo::SHA1, &k1), t).unwrap().0, s1);
            assert_eq!(code_at(&ent(Algo::SHA256, &k256), t).unwrap().0, s256);
            assert_eq!(code_at(&ent(Algo::SHA512, &k512), t).unwrap().0, s512);
        }
    }

    #[test]
    fn otpauth() {
        let e = parse_otpauth("otpauth://totp/GitHub:b0ris8?secret=jbswy3dpehpk3pxp&issuer=GitHub&digits=6&period=30").unwrap();
        assert_eq!(e.name, "GitHub (b0ris8)");
        assert_eq!(e.secret, "JBSWY3DPEHPK3PXP");
        let e = parse_otpauth("otpauth://totp/My%20Bank?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8").unwrap();
        assert_eq!(e.name, "My Bank");
        assert_eq!(e.algorithm, Algo::SHA256);
        assert_eq!(e.digits, 8);
        assert!(parse_otpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_none());
    }
}
