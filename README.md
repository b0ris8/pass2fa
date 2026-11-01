# pass2fa — локальные пароли и 2FA

egui/eframe (wgpu, только Wayland), без GTK/порталов/DBus. Хранилище — два файла стандартного age
(схема «ключ, обёрнутый паролем», как в KeePass):

- `vault.key.age` — случайный ключ хранилища (X25519), зашифрованный мастер-паролем (scrypt 2^20 — медленно
  нарочно, только при входе и смене пароля);
- `vault.age` — данные (JSON), зашифрованные этим ключом (ChaCha20-Poly1305): сохранение — миллисекунды.

**В бэкап — оба файла.** Без `vault.key.age` данные не открыть даже с паролем; смена пароля перешифровывает
только ключ (прежний — в `vault.key.age.before-passwd-*`). Старый формат (один файл по паролю) при первом
входе мигрирует сам, исходник — в `vault.age.legacy`.

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

Восстановление без программы: `age -d -i vault.key.age vault.age > vault.json` (age спросит пароль).

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

## Группы паролей
Слева — группы как фильтр («Все группы», свои, «Без группы»). Запись переносится перетаскиванием
за иконку/имя на группу или ПКМ → «Переместить в группу»; ПКМ по группе — переименовать/удалить
(записи не удаляются, уходят в «Без группы»). Импорт берёт группы из Bitwarden `folder`,
Proton Pass `vault`, KeePass `Group`, PassVault `category`; экспорт в PassVault пишет группу в `category`.

## Генератор
Над списком паролей: «Сгенерировать в буфер» (или Ctrl+G) — новый пароль сразу в буфере, без создания записи.

## Браузер (native messaging, без демона)
Браузер сам запускает `pass2fa` на каждый запрос и закрывает его. Разблокировка общая для окна,
расширения и CLI: в kernel keyring пользователя лежит только ключ хранилища (не мастер-пароль),
30 мин без обращений, на диск не пишется. «Блок»/Ctrl+L в окне и `pass2fa lock` закрывают всё.
Заполнение только по действию (клик / Alt+Shift+L — логин, Alt+Shift+O — TOTP, Alt+Shift+P — окно),
только https (http — лишь для localhost), хост и порт сравниваются строго (`dev1step.com:6493` ≠ `dev1step.com`),
поля ищутся и в shadow DOM, и во фреймах того же сайта; чужие фреймы не заполняются.

    install -Dm755 target/release/pass2fa ~/.local/bin/pass2fa
    ~/.local/bin/pass2fa install-browser      # манифест хоста указывает на этот бинарник
    ./tools/build-extension.sh                # extension/dist/{firefox,chromium}, pass2fa-firefox.xpi

- Chromium/Brave/Vivaldi: `chrome://extensions` → режим разработчика → «Загрузить распакованное» → `extension/dist/chromium`
  (id фиксирован ключом в манифесте: `mppimlmnkoibdoennahbdmclgegncjed`).
- LibreWolf / Firefox ESR / Developer Edition: `about:config` → `xpinstall.signatures.required = false`,
  затем `about:addons` → «Установить из файла» → `extension/dist/pass2fa-firefox.xpi`.
- Обычный Firefox неподписанное расширение насовсем не ставит: либо `about:debugging` (до перезапуска),
  либо подпись «unlisted» через AMO (нужен аккаунт Mozilla).
- Windows: хост пока не реализован (нужен ключ реестра HKCU и DPAPI вместо keyring).
