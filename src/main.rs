mod bundle;
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
  pass2fa install                  установить: программа в постоянное место (Linux ~/.local/bin,
                                   Windows %LOCALAPPDATA%\\pass2fa), хост для браузеров, файлы расширения, ярлык
  pass2fa uninstall                убрать всё это (хранилище не трогается)
  pass2fa install-browser          только хост native messaging + файлы расширения (для этого бинарника)
  pass2fa uninstall-browser        убрать их
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
        Some("install") => cli_install(),
        Some("uninstall") => {
            for p in native::uninstall().into_iter().chain(desktop::uninstall()) { eprintln!("удалено: {}", p.display()); }
            if let Ok(exe) = installed_exe() {
                eprintln!("программу удали сам: {}", exe.display());
            }
            Ok(())
        }
        Some("install-browser") => native::install().map(|w| {
            for p in w { eprintln!("записано: {}", p.display()); }
            extension_hint();
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
    // подсказку печатаем сами: rpassword на Windows пишет её в CONOUT$ байтами — кириллица ломается
    eprint!("{prompt}");
    rpassword::read_password().map(SecretString::from).map_err(|e| e.to_string())
}

/// Постоянное место программы: оттуда её запускают браузер и ярлык, сборку можно удалять/пересобирать.
fn installed_exe() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        Ok(dirs::data_local_dir().ok_or("нет %LOCALAPPDATA%")?.join("pass2fa").join("pass2fa.exe"))
    }
    #[cfg(not(windows))]
    {
        Ok(dirs::home_dir().ok_or("нет $HOME")?.join(".local").join("bin").join("pass2fa"))
    }
}

/// Скопировать бинарник на место, не мешая запущенной копии: рядом .new → переименование поверх.
/// Windows не даёт перезаписать запущенный exe, но даёт его переименовать — старый уходит в .old.
fn place_exe(src: &std::path::Path, dst: &std::path::Path) -> Result<(), String> {
    if let Some(d) = dst.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let new = dst.with_extension("new");
    std::fs::copy(src, &new).map_err(|e| format!("{}: {e}", new.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }
    if std::fs::rename(&new, dst).is_err() {
        let old = dst.with_extension("old");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(dst, &old).map_err(|e| format!("{}: {e} (закрой окно pass2fa и повтори)", dst.display()))?;
        std::fs::rename(&new, dst).map_err(|e| format!("{}: {e}", dst.display()))?;
    }
    Ok(())
}

fn cli_install() -> Result<(), String> {
    let cur = std::env::current_exe().map_err(|e| e.to_string())?;
    let dst = installed_exe()?;
    if std::fs::canonicalize(&cur).ok() != std::fs::canonicalize(&dst).ok() {
        place_exe(&cur, &dst)?;
    }
    eprintln!("программа: {}", dst.display());
    // дальше — от имени установленной копии: манифест браузера и ярлык указывают на неё
    let mut steps = vec!["install-browser"];
    if cfg!(unix) {
        steps.push("install-desktop");
    }
    for s in steps {
        let st = std::process::Command::new(&dst).arg(s).status().map_err(|e| format!("{} {s}: {e}", dst.display()))?;
        if !st.success() {
            return Err(format!("{} {s}: ошибка (см. выше)", dst.display()));
        }
    }
    #[cfg(windows)]
    eprintln!("\nЧтобы звать просто `pass2fa` из терминала, добавь папку в PATH пользователя (один раз):\n  [Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path','User') + ';{}', 'User')",
        dst.parent().map(|p| p.display().to_string()).unwrap_or_default());
    Ok(())
}

fn extension_hint() {
    let d = bundle::dir();
    eprintln!(
        "\nРасширение (ставится один раз; при обновлении программы — переустановить тем же способом):\n\
         \u{20} LibreWolf/Firefox ESR: about:config → xpinstall.signatures.required = false;\n\
         \u{20}   about:addons → ⚙ → «Установить дополнение из файла…» → {}\n\
         \u{20} Chromium/Chrome/Brave: chrome://extensions → «Режим разработчика» → «Загрузить распакованное» → {}\n\
         \u{20} id: Firefox {}, Chromium {}",
        d.join("pass2fa-firefox.xpi").display(),
        d.join("chromium").display(),
        native::FIREFOX_EXT_ID,
        native::CHROMIUM_EXT_ID
    );
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
