# pass2fa — локальные пароли и 2FA

Менеджер паролей и TOTP-кодов: всё хранится у тебя в двух зашифрованных файлах, без аккаунтов, облака и сети.
Есть окно, команды для терминала и расширение для браузера, которое подставляет логин, пароль и код 2FA.

Linux (Wayland) и Windows 10/11. Браузеры: LibreWolf, Firefox ESR, Chromium, Chrome, Brave.

---

## Просто установить

### Linux

1. Скачай `pass2fa-<версия>-linux-x86_64.tar.gz` со страницы **Releases**.
2. В терминале:

       tar xzf pass2fa-*-linux-x86_64.tar.gz
       cd pass2fa-*-linux-x86_64
       ./pass2fa install

Программа ляжет в `~/.local/bin/pass2fa` (папка должна быть в `PATH`), появится в меню приложений.

### Windows

1. Скачай `pass2fa-<версия>-windows-x86_64.zip` со страницы **Releases** и распакуй.
2. Запусти `install.cmd` двойным щелчком. Если Windows покажет «Система Windows защитила ваш компьютер» —
   «Подробнее» → «Выполнить в любом случае» (программа не подписана сертификатом).

Появится ярлык **pass2fa** в меню «Пуск» (его можно закрепить на панели задач). Права администратора не нужны.

### Расширение для браузера (один раз в каждом браузере)

`install` в конце пишет, где лежат файлы расширения
(Linux: `~/.local/share/pass2fa/extension/`, Windows: `%LOCALAPPDATA%\pass2fa\extension\`).

- **LibreWolf / Firefox ESR**: открой `about:config`, поставь `xpinstall.signatures.required` = `false`.
  Затем `about:addons` → ⚙ → «Установить дополнение из файла…» → `pass2fa-firefox.xpi`.
- **Chromium / Chrome / Brave**: `chrome://extensions` → включи «Режим разработчика» →
  «Загрузить распакованное» → папка `chromium`.
- Обычный Firefox такие расширения насовсем не ставит.

После установки перезапусти браузер.

---

## Пользоваться

- **Окно**: запусти pass2fa из меню. При первом запуске задаёшь мастер-пароль (от 10 символов).
- **Браузер**: на странице входа нажми значок pass2fa → «Заполнить» / «Вставить код».
  Горячие клавиши: Alt+Shift+L — логин, Alt+Shift+O — код 2FA, Alt+Shift+P — окно расширения.
  Разблокировка общая: открыл хранилище в окне — браузер тоже разблокирован (30 мин).
- **Перенос из других программ**: `pass2fa import файл` — Proton Pass, Bitwarden, Chrome/Firefox (CSV),
  Aegis, 2FAS, Proton Authenticator, PassVault (JSON), ссылки `otpauth://`.
- **Код в терминале**: `pass2fa code github` (Linux: `| wl-copy` — сразу в буфер).
- Ctrl+F — поиск, Ctrl+G — новый пароль в буфер, Ctrl+L — заблокировать всё.

### Где данные и как их не потерять

| | Linux | Windows |
|---|---|---|
| Хранилище | `~/.local/share/2FApass/` | `%LOCALAPPDATA%\2FApass\` |

Файлов два: **`vault.age` и `vault.key.age` — бэкапь и переноси только вместе.** Без пароля они бесполезны,
без `vault.key.age` не откроются даже с паролем.

На другой компьютер — скопируй оба файла в ту же папку там. Копии на разных машинах независимы:
изменения сами не синхронизируются.

Открыть без программы: `age -d -i vault.key.age vault.age > vault.json` (age спросит пароль).

### Обновить или удалить

- Обновить — установить новую версию тем же способом, поверх. Если в описании релиза сказано, что изменилось
  расширение, — переустанови и его.
- Удалить — `pass2fa uninstall` (хранилище остаётся).

### Если что-то не так

- **«pass2fa не отвечает … No such native application»** — не выполнен `install` или браузер не перезапущен.
- **«неверный пароль»** — проверь раскладку в этом окне; кнопка «глаз» показывает введённое.
- **«vault.age не от этого ключа»** — `vault.age` и `vault.key.age` из разных копий, скопируй оба заново.

---

## Собрать из исходников

### Linux (Artix и др.)

    sudo pacman -S rustup && rustup default stable      # один раз
    git clone https://github.com/b0ris8/pass2fa.git
    cd pass2fa
    cargo build --release
    ./target/release/pass2fa install

### Windows

Один раз, PowerShell от администратора:

    choco install -y visualstudio2022-workload-vctools rustup.install
    rustup default stable-x86_64-pc-windows-msvc

Сборка (обычный PowerShell):

    git clone https://github.com/b0ris8/pass2fa.git C:\WorkDev\pass2fa
    cd C:\WorkDev\pass2fa
    cargo build --release
    .\target\release\pass2fa.exe install

Репозиторий на сетевом или облачном диске — собирай с `--target-dir C:\build\pass2fa`,
чтобы папка `target` не синхронизировалась.

### Обновление из исходников

    git pull
    cargo build --release
    ./target/release/pass2fa install        # Windows: .\target\release\pass2fa.exe install

Программа заменяется на месте, даже если окно pass2fa открыто.

### Выпустить релиз

Версию поднять в `Cargo.toml` (`version = "…"`), закоммитить, затем:

    git tag v0.3.0
    git push origin v0.3.0

GitHub Actions (`.github/workflows/release.yml`) соберёт Linux и Windows и выложит в Releases:
`pass2fa-v0.3.0-linux-x86_64.tar.gz`, `pass2fa-v0.3.0-windows-x86_64.zip` и их `.sha256`.
Ход сборки — вкладка **Actions**. Проверочная сборка без релиза: Actions → release → «Run workflow».

### Что в репозитории

- `src/main.rs` — `pass2fa`: CLI, хост для браузера, окно; `src/bin/pass2faw.rs` — окно без консоли (Windows);
  остальное в `src/` — общая библиотека.
- `extension/` — расширение браузера; встраивается в бинарник, `install` раскладывает его сам.
  Для разработки: `./tools/build-extension.sh` → `extension/dist/`.
- `assets/pass2fa.svg` — иконка; `assets/pass2fa.res` — она же для exe (подключает `build.rs`).
  Поменял SVG — `./tools/gen-win-icon.sh` на Linux.
- Скриншоты при разработке: `cargo build --release --features devshot`, затем
  `PASS2FA_DEV_PASS=… PASS2FA_DEV_TAB=codes|logins|settings|edit|picker|lock PASS2FA_DEV_SHOT=/tmp/x.png pass2fa`.

---

## Подробности

### Хранилище
Два файла стандартного формата age (схема «ключ, обёрнутый паролем», как в KeePass):
`vault.key.age` — случайный ключ хранилища (X25519), зашифрованный мастер-паролем (scrypt 2^20, вход ~1 с);
`vault.age` — данные (JSON), зашифрованные этим ключом: сохранение — миллисекунды.
Смена пароля перешифровывает только ключ (прежний — в `vault.key.age.before-passwd-*`).
После каждого сохранения предыдущая версия — `vault.age.bak`. Старый формат (один файл по паролю)
при первом входе мигрирует сам, исходник — в `vault.age.legacy`. Другой путь — `--vault <путь>` или `PASS2FA_VAULT`.

Автоблокировка окна — 5 мин; буфер обмена очищается через 20 с (на Wayland — пока открыто окно).

### Браузер
Браузер сам запускает `pass2fa` на каждый запрос и закрывает его — фонового процесса нет.
Общая разблокировка хранит только ключ хранилища (не мастер-пароль), 30 мин без обращений:
Linux — kernel keyring пользователя, на диск не пишется; Windows — ключ под DPAPI (учётная запись Windows)
в `%LOCALAPPDATA%\pass2fa\session.bin`, стирается по сроку и при блокировке.

Заполнение только по действию пользователя, только https (http — лишь localhost), хост и порт сравниваются строго
(`dev1step.com:6493` ≠ `dev1step.com`); поля ищутся в shadow DOM и во фреймах того же сайта, чужие фреймы не заполняются.

Что регистрирует `install`: Linux — манифесты в `~/.mozilla`, `~/.librewolf` и папках Chromium-браузеров (где есть профиль);
Windows — манифесты в `%LOCALAPPDATA%\pass2fa\NativeMessagingHosts\` и ключи
`HKCU\Software\{Mozilla,LibreWolf,Google\Chrome,Chromium}\NativeMessagingHosts\pass2fa`.
Id расширения: Firefox `pass2fa@b0ris8`, Chromium `mppimlmnkoibdoennahbdmclgegncjed`.
Только хост и расширение, без копирования программы: `pass2fa install-browser`.

### Какие записи показываются на сайте
- **Пароль** — по `URL` и «Доп. сайты». Пустой URL — берётся имя, если похоже на домен.
  Поддомены подходят (`google.com` → `accounts.google.com`), порт — строго.
- **2FA** — если заполнены «Сайты», только на них. Иначе — по Issuer против домена вкладки
  (`GitHub` → `github.com`). Имя аккаунта и почта не участвуют.
- **Равнозначные домены** (Настройки): строка — домены одного сервиса. Сохранён корень группы (`proton.me`) —
  подходит и `protonmail.com`; сохранён поддомен (`account.proton.me`) — только он сам.
  Для 2FA по Issuer тоже работает: `Proton` ↔ protonmail.com, `Anthropic` ↔ claude.ai, `OpenAI` ↔ chatgpt.com.
- Импорт CSV: несколько адресов в URL → первый в URL, остальные в доп. сайты.

### Окно
- Группы паролей слева; перенос — перетаскиванием или ПКМ → «Переместить в группу».
  Импорт берёт группы из Bitwarden `folder`, Proton Pass `vault`, KeePass `Group`, PassVault `category`.
- Иконки сервисов — офлайн, встроенный набор Simple Icons (CC0). Своя — `si:<slug>` или путь к PNG/JPEG.
- Выбор файла — встроенный, без GTK/порталов: поле сверху фильтрует, путь `/…` или `~/…` + Enter — переход.
- Linux: ярлык и иконка — `~/.local/share/applications/pass2fa.desktop` + `icons/hicolor` (окно обновляет их само).
  Windows: ярлык в «Пуске» ведёт на `pass2faw.exe` — то же окно без консоли.

### Экспорт (разовый перенос на телефон)
    pass2fa export-aegis a.json        # 2FA → Aegis
    pass2fa export-passvault p.json    # пароли → PassVault
Файлы открытые — после импорта удали (`shred -u`).
