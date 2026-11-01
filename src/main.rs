mod desktop;
mod export;
mod filepick;
mod gen;
mod icons;
mod gui;
mod import;
mod model;
mod native;
mod session;
mod state;
mod totp;
mod vault;

use age::secrecy::SecretString;
use std::path::PathBuf;

const USAGE: &str = "pass2fa — локальные пароли и 2FA (age-шифрование)

  pass2fa                          GUI
  pass2fa import <файл>...         импорт JSON/CSV/otpauth в хранилище (создаст его при отсутствии)
  pass2fa code <подстрока имени>   напечатать текущий TOTP-код (для скриптов: | wl-copy)
  pass2fa export-aegis <файл>      2FA в открытый JSON для импорта в Aegis (после переноса удалить!)
  pass2fa export-passvault <файл>  пароли в открытый JSON для PassVault (после переноса удалить!)
  pass2fa install-browser          манифест native messaging для Firefox/LibreWolf/Chromium (браузерное расширение)
  pass2fa uninstall-browser        убрать его
  pass2fa lock                     заблокировать общую сессию (GUI/браузер), стереть ключи из keyring
  pass2fa install-desktop          .desktop + иконка в ~/.local/share (GUI делает это сам при старте)
  pass2fa uninstall-desktop        убрать их

  --vault <путь>   файл хранилища (иначе $PASS2FA_VAULT или ~/.local/share/2FApass/vault.age)
  Рядом vault.key.age — ключ, зашифрованный паролем. В бэкап — ОБА файла.
  Восстановление без программы:  age -d -i vault.key.age vault.age";

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // запуск браузером как native messaging host: только stdin/stdout, без GUI
    if native::invoked_by_browser(&args) || args.first().map(String::as_str) == Some("native-host") {
        native::run(&vault::default_path());
        return;
    }
    let mut path = vault::default_path();
    if let Some(i) = args.iter().position(|a| a == "--vault") {
        if i + 1 >= args.len() { die("--vault: нужен путь"); }
        path = PathBuf::from(args.remove(i + 1));
        args.remove(i);
    }
    let r = match args.first().map(String::as_str) {
        None => gui::run(path).map_err(|e| e.to_string()),
        Some("import") if args.len() > 1 => cli_import(&path, &args[1..]),
        Some("code") if args.len() == 2 => cli_code(&path, &args[1]),
        Some("export-aegis") if args.len() == 2 => cli_export_aegis(&path, &args[1]),
        Some("export-passvault") if args.len() == 2 => cli_export_passvault(&path, &args[1]),
        Some("install-browser") => native::install().map(|w| {
            for p in w { eprintln!("записано: {}", p.display()); }
            eprintln!("Firefox/LibreWolf: id расширения {}; Chromium: {}", native::FIREFOX_EXT_ID, native::CHROMIUM_EXT_ID);
        }),
        Some("uninstall-browser") => {
            for p in native::uninstall() { eprintln!("удалено: {}", p.display()); }
            Ok(())
        }
        Some("lock") => {
            session::clear();
            eprintln!("сессия заблокирована");
            Ok(())
        }
        Some("install-desktop") => desktop::ensure_installed().map(|w| {
            if w.is_empty() { eprintln!("уже установлено"); }
            for p in w { eprintln!("записано: {}", p.display()); }
        }),
        Some("uninstall-desktop") => {
            for p in desktop::uninstall() { eprintln!("удалено: {}", p.display()); }
            Ok(())
        }
        Some("-h" | "--help" | "help") => { println!("{USAGE}"); Ok(()) }
        _ => Err(USAGE.to_string()),
    };
    if let Err(e) = r { die(&e); }
}

fn die(e: &str) -> ! {
    eprintln!("{e}");
    std::process::exit(1)
}

fn ask(prompt: &str) -> Result<SecretString, String> {
    rpassword::prompt_password(prompt).map(SecretString::from).map_err(|e| e.to_string())
}

/// Открыть хранилище: из общей сессии (если разблокировано) или по паролю; нет файла — создать.
fn open_or_create(path: &PathBuf) -> Result<(model::Vault, age::x25519::Identity), String> {
    use age::secrecy::ExposeSecret;
    if vault::exists(path) {
        if let Some(x) = session::load(path)? {
            return Ok(x);
        }
        let p = ask("Пароль хранилища: ")?;
        vault::unlock(path, &p)
    } else {
        eprintln!("Хранилища {} нет — создаю.", path.display());
        let p1 = ask("Новый пароль: ")?;
        let p2 = ask("Повтор: ")?;
        if p1.expose_secret() != p2.expose_secret() { return Err("пароли не совпали".into()); }
        if p1.expose_secret().chars().count() < 10 { return Err("пароль короче 10 символов".into()); }
        let v = model::Vault::default();
        let id = vault::create(path, &p1, &v)?;
        Ok((v, id))
    }
}

fn cli_import(path: &PathBuf, files: &[String]) -> Result<(), String> {
    let (mut v, id) = open_or_create(path)?;
    for f in files {
        let st = v.merge(import::from_file(std::path::Path::new(f))?);
        eprintln!("{f}: {st}");
    }
    vault::save(path, &id, &v)?;
    eprintln!("Сохранено: {} (2FA: {}, паролей: {})", path.display(), v.codes.len(), v.passwords.len());
    eprintln!("Исходные открытые файлы удали сам (shred -u <файл>), после проверки в GUI.");
    Ok(())
}

fn cli_code(path: &PathBuf, needle: &str) -> Result<(), String> {
    let (v, _) = open_or_create(path)?;
    let n = needle.to_lowercase();
    let hits: Vec<_> = v.codes.iter().filter(|c| c.name.to_lowercase().contains(&n)).collect();
    match hits.as_slice() {
        [one] => {
            let (code, _) = totp::code(one).ok_or("битый секрет")?;
            println!("{code}");
            Ok(())
        }
        [] => Err("не найдено".into()),
        many => Err(format!("неоднозначно: {}", many.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", "))),
    }
}

fn cli_export_aegis(path: &PathBuf, out: &str) -> Result<(), String> {
    let (v, _) = open_or_create(path)?;
    let n = export::aegis_to_file(&v, std::path::Path::new(out))?;
    eprintln!("{n} записей 2FA -> {out} (ОТКРЫТЫЙ ТЕКСТ). Aegis: Настройки → Импорт и экспорт → Импорт из файла → Aegis.");
    eprintln!("После импорта удали файл везде: shred -u {out} (и на устройстве).");
    Ok(())
}

fn cli_export_passvault(path: &PathBuf, out: &str) -> Result<(), String> {
    let (v, _) = open_or_create(path)?;
    let n = export::passvault_to_file(&v, std::path::Path::new(out))?;
    eprintln!("{n} паролей -> {out} (ОТКРЫТЫЙ ТЕКСТ). PassVault: Настройки → Импорт → PassVault JSON, пароль файла пустой.");
    eprintln!("После импорта удали файл везде: shred -u {out} (и на устройстве).");
    Ok(())
}
