//! GUI без консольного окна: на Windows — для ярлыка в «Пуске» (pass2fa.exe консольный ради CLI и браузера).
//! На Linux не устанавливается: там `pass2fa` без аргументов делает то же самое.
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    if let Err(e) = otp_local_gui::gui::run(otp_local_gui::vault::default_path()) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
