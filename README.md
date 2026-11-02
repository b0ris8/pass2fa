# pass2fa — локальные пароли и 2FA

egui/eframe (wgpu), без GTK/порталов/DBus. Linux (Wayland) и Windows 10/11; браузерное расширение для LibreWolf/Firefox и Chromium. Хранилище — два файла стандартного age
(схема «ключ, обёрнутый паролем», как в KeePass):

- `vault.key.age` — случайный ключ хранилища (X25519), зашифрованный мастер-паролем (scrypt 2^20 — медленно
  нарочно, только при входе и смене пароля);
- `vault.age` — данные (JSON), зашифрованные этим ключом (ChaCha20-Poly1305): сохранение — миллисекунды.

**В бэкап — оба файла.** Без `vault.key.age` данные не открыть даже с паролем; смена пароля перешифровывает
только ключ (прежний — в `vault.key.age.before-passwd-*`). Старый формат (один файл по паролю) при первом
входе мигрирует сам, исходник — в `vault.age.legacy`.

## Установка — Linux (Artix и др.)

Нужен Rust (`pacman -S rustup && rustup default stable`).

    git clone https://github.com/b0ris8/pass2fa.git ~/WorkDev/repositories/GitHub/pass2fa
    cd ~/WorkDev/repositories/GitHub/pass2fa
    cargo build --release
    ./target/release/pass2fa install

`install` делает всё сразу:
- копирует программу в `~/.local/bin/pass2fa` (папка должна быть в `PATH`);
- регистрирует хост для браузеров (`~/.mozilla`, `~/.librewolf`, Chromium-семейство — где есть профиль);
- раскладывает расширение в `~/.local/share/pass2fa/extension/` (`pass2fa-firefox.xpi` и папку `chromium/`);
- создаёт ярлык и иконку в меню (`~/.local/share/applications`).

## Установка — Windows 10/11

Нужен Rust с MSVC (один раз, PowerShell от администратора):

    choco install -y visualstudio2022-workload-vctools rustup.install
    rustup default stable-x86_64-pc-windows-msvc

Сборка и установка (обычный PowerShell, без администратора):

    git clone https://github.com/b0ris8/pass2fa.git C:\WorkDev\pass2fa
    cd C:\WorkDev\pass2fa
    cargo build --release
    .\target\release\pass2fa.exe install

`install` копирует программу в `%LOCALAPPDATA%\pass2fa\pass2fa.exe`, пишет манифесты хоста в
`%LOCALAPPDATA%\pass2fa\NativeMessagingHosts\` и ключи `HKCU\Software\{Mozilla,LibreWolf,Google\Chrome,Chromium}\NativeMessagingHosts\pass2fa`,
раскладывает расширение в `%LOCALAPPDATA%\pass2fa\extension\`. Администратор не нужен, всё в профиле пользователя.
В конце печатает команду, чтобы добавить папку программы в `PATH`.

Сборка на сетевом/облачном диске (`P:\…`): собирай с `--target-dir C:\build\pass2fa`, чтобы `target` не синхронизировался.

## Расширение браузера (один раз на браузер)

- **LibreWolf / Firefox ESR / Developer Edition**: `about:config` → `xpinstall.signatures.required = false`;
  `about:addons` → ⚙ → «Установить дополнение из файла…» → `pass2fa-firefox.xpi` из папки расширения (см. выше).
- **Chromium / Chrome / Brave**: `chrome://extensions` → «Режим разработчика» → «Загрузить распакованное» → папка `chromium`.
- Обычный Firefox неподписанное расширение насовсем не ставит: только `about:debugging` (до перезапуска).

Расширение встроено в бинарник — версия всегда совпадает с программой. Профиль браузера, перенесённый
с другой машины, уже содержит расширение: достаточно `pass2fa install` (нужен только хост).

## Обновление

    git pull
    cargo build --release          # Windows: … --target-dir C:\build\pass2fa
    ./target/release/pass2fa install

Программа заменяется на месте, даже если окно pass2fa открыто (Windows: старая копия уходит в `pass2fa.old`).
Если изменилось расширение (`extension/`), переустанови его в браузере из того же файла.
Удаление — `pass2fa uninstall`: хранилище не трогается.

## Хранилище и перенос между машинами

- Linux: `~/.local/share/2FApass/` · Windows: `%LOCALAPPDATA%\2FApass\`; другой путь — `--vault <путь>` или `PASS2FA_VAULT`.
- Файлов два, **переносить и бэкапить только парой**: `vault.age` и `vault.key.age`.
- Копии на разных машинах независимы: правка на одной не попадёт на другую. Держи одну основную,
  на остальные копируй оба файла заново (например, `scp "host:.local/share/2FApass/vault*.age" "$env:LOCALAPPDATA\2FApass\"`).
- «vault.age не от этого ключа» — файлы из разных копий; «неверный пароль» — неверный пароль
  (в окне и браузере проверь раскладку: кнопка «глаз» показывает введённое).

## Использование
    pass2fa                       # GUI
    pass2fa import файл...        # JSON: свой старый, PassVault, Proton Authenticator, Aegis (plaintext), 2FAS…;
                                  # CSV: Proton Pass, Chrome/Firefox, Bitwarden; текст с otpauth://
    pass2fa code github | wl-copy # код в буфер из скрипта/хоткея labwc
    pass2fa export-aegis a.json   # 2FA в открытый JSON для Aegis (разовый перенос, потом shred -u)
    pass2fa export-passvault p.json # пароли в открытый JSON для PassVault (Android); импорт его JSON — обычным import

После каждого сохранения предыдущая версия хранилища — `vault.age.bak`.

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
расширения и CLI, хранится только ключ хранилища (не мастер-пароль), 30 мин без обращений:
- Linux — kernel keyring пользователя, на диск не пишется;
- Windows — ключ, зашифрованный DPAPI (учётная запись Windows), в `%LOCALAPPDATA%\pass2fa\session.bin`;
  прочитать может только этот пользователь на этой машине, по истечении срока или при блокировке файл стирается.

«Блок»/Ctrl+L в окне и `pass2fa lock` закрывают всё.
Заполнение только по действию (клик / Alt+Shift+L — логин, Alt+Shift+O — TOTP, Alt+Shift+P — окно),
только https (http — лишь для localhost), хост и порт сравниваются строго (`dev1step.com:6493` ≠ `dev1step.com`),
поля ищутся и в shadow DOM, и во фреймах того же сайта; чужие фреймы не заполняются.

Только хост и файлы расширения, без копирования программы: `pass2fa install-browser` (манифест укажет на этот бинарник).
Сборка расширения в `extension/dist/` для разработки: `./tools/build-extension.sh`.

Если расширение пишет «pass2fa не отвечает … No such native application» — не выполнен `pass2fa install`
(или браузер не перезапущен после него).

### Какие записи показываются на сайте
- **Пароль** — по `URL` и «Доп. сайты» (по одному на строку). Пустой URL — берётся имя, если оно похоже на домен.
  Поддомены подходят (`google.com` → `accounts.google.com`), порт — строго.
- **2FA** — если заполнены «Сайты» — только на них (как пароли). Если пусто — по Issuer против домена
  вкладки: Issuer `GitHub` → `github.com`. Имя аккаунта и почта в сопоставлении не участвуют.
- **Равнозначные домены** (Настройки): строка — группа доменов одного сервиса. Сохранён корень группы
  (`proton.me`) — подходит и `protonmail.com`, и `mail.protonmail.com`. Сохранён поддомен (`account.proton.me`) —
  только он сам: так чужой `tenant.example.net` не наследует всю группу. Для 2FA по Issuer группа тоже работает:
  `Proton` ↔ protonmail.com, `Anthropic` ↔ claude.ai, `OpenAI` ↔ chatgpt.com.
  Группы лежат в хранилище (переезжают вместе с ним); «По умолчанию» восстанавливает стартовый набор.
- Импорт CSV: несколько адресов в поле URL → первый в URL, остальные в доп. сайты; TOTP из такой записи
  привязывается к её адресам.
