# pass2fa — локальные пароли и 2FA

egui/eframe (wgpu, только Wayland), без GTK/порталов/DBus. Одно хранилище — `vault.age`:
JSON, зашифрованный стандартным age по паролю (scrypt).

## Сборка
    cargo build --release
    install -Dm755 target/release/pass2fa ~/.local/bin/pass2fa

## Использование
    pass2fa                       # GUI
    pass2fa import файл...        # JSON: свой старый, PassVault, Proton Authenticator, Aegis (plaintext), 2FAS…;
                                  # CSV: Proton Pass, Chrome/Firefox, Bitwarden; текст с otpauth://
    pass2fa code github | wl-copy # код в буфер из скрипта/хоткея labwc
    pass2fa export-aegis a.json   # 2FA в открытый JSON для Aegis (разовый перенос, потом shred -u)
    pass2fa export-passvault p.json # пароли в открытый JSON для PassVault (Android); импорт его JSON — обычным import

Хранилище: `~/.local/share/2FApass/vault.age` (Windows: `%LOCALAPPDATA%\2FApass\vault.age`),
другой путь — `--vault <путь>` или `PASS2FA_VAULT`. После каждого сохранения предыдущая версия — `vault.age.bak`.

Восстановление без программы: `age -d vault.age > vault.json`.

Автоблокировка 5 мин, Ctrl+L — блок, Ctrl+F — поиск; буфер очищается через 20 с
(на Wayland содержимое буфера живёт, пока открыто окно).

Иконка приложения: на Wayland окно само иконку не ставит, её находит панель по app_id `pass2fa`
через `~/.local/share/applications/pass2fa.desktop` + `icons/hicolor/{scalable,256x256}/apps/pass2fa.*`.
GUI создаёт/обновляет их при старте (пишет только при изменении); вручную — `pass2fa install-desktop` / `uninstall-desktop`.

Выбор файла — встроенный (без GTK/порталов): поле сверху фильтрует по имени, путь `/…` или `~/…` + Enter — переход;
последняя папка запоминается в `~/.config/pass2fa/state.json` (только путь).

Иконки сервисов — офлайн, встроенный набор Simple Icons (CC0): подбор по issuer/имени/домену URL.
Своя иконка — в карточке записи: `si:<slug>` из набора или путь к PNG/JPEG; пусто — автоподбор.

Скриншоты при разработке (не входит в обычную сборку):
    cargo build --release --features devshot
    PASS2FA_DEV_PASS=… PASS2FA_DEV_TAB=codes|logins|settings|edit|picker|lock PASS2FA_DEV_SHOT=/tmp/x.png pass2fa
