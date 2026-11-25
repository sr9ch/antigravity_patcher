# antigravity-region-fix

Локальный патч регионального гейта **Antigravity CLI (`agy`)** и бэкендов
Antigravity для Linux, macOS и Windows. Позволяет использовать уже авторизованный
Google-аккаунт без VPN, прокси, смены DNS и смены региона аккаунта.

Проверено на `agy 1.5.13`–`1.5.17`, Fedora Linux 45, x86-64, аккаунт с
обычной consumer-авторизацией. Поддержка macOS (Mach-O, включая
universal-бинарники) реализована и покрыта юнит-тестами, но на реальном Mac
ещё не прогонялась — см. раздел 3.1. Windows (PE32+ x64 и arm64) проверен на
официальных сборках 1.5.17 из GitHub Releases: сигнатуры найдены и патч
применяется, но запуск пропатченного `.exe` на Windows не проверялся — см.
раздел 3.2.

## Установка

```bash
git clone https://github.com/sr9ch/antigravity_patcher.git
cd antigravity_patcher

make test        # 22 юнит-теста; установленный agy не обязателен
make install     # ставит ~/.local/bin/agy-region-fix и модуль в ~/.local/lib
```

Без установки всё работает прямо из каталога: `./agy-region-fix status`.

Другие способы:

```bash
pipx install .                     # через pyproject.toml, команда agy-region-fix
make install PREFIX=/usr/local     # системная установка (нужен sudo)
make uninstall                     # убрать саму утилиту
```

`make uninstall` не трогает ни `agy`, ни приложение и не удаляет резервные
копии в `~/.local/share/antigravity-region-fix/`.

---

## 1. Что именно блокирует CLI

Ошибка воспроизводится так:

```console
$ agy -p "Reply with exactly OK"
error: Eligibility check failed: Your current account is not eligible for
Antigravity, because it is not currently available in your location.
$ echo $?
1
```

Диагностика (лог `~/.gemini/antigravity-cli/log/cli-*.log`):

```
I ... keyringAuth: loaded token, ... expired=false
I ... server_oauth.go:221] applyAuthResult: email=..., authMethod=consumer
I ... URL: https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist
I ... URL: https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels
W ... server_oauth.go:133] Account ineligible: Your current account is not eligible
      for Antigravity, because it is not currently available in your location.
E ... printmode.go:297] Print mode: eligibility check failed: ...
```

Разбор:

| Слой | Что происходит | Кто решает |
|---|---|---|
| OAuth | токен из keyring валиден, вход выполнен | Google OAuth |
| `loadCodeAssist` | сервер возвращает ineligible-тир с причиной `REGION_OUT_OF_SCOPE` | сервер |
| `fetchAvailableModels` | **успешно**, список моделей приходит | сервер |
| локальный гейт `hasValidAuth` | CLI читает флаг из ответа и **сам** выбирает ветку «недоступно» | **клиент** |
| `streamGenerateContent` | после снятия клиентского гейта **успешно отвечает** | сервер |

То есть блокировка — это **клиентское решение по серверной подсказке**, а не отказ
модельного API. Именно поэтому адресный патч клиента даёт реальную генерацию,
а не просто убирает экран ошибки.

Найденные в бинарнике точки (Go, символы сохранились в pclntab):

* `google3/third_party/jetski/cli/backend/backend.applyIneligibilityURLs`
* `google3/third_party/jetski/cli/backend/backend.IneligibilityFromResult`
* `...handleAuthResult` — гейт обычного CLI;
* `authclient.(*PersonalAuthValidator).Validate` — гейт режима `agy --hub`
  (его использует IDE-расширение).

### Важное ограничение

Патч **не создаёт серверных прав**. Если Google начнёт отклонять сам модельный
запрос (HTTP 400 `FAILED_PRECONDITION`, `User location is not supported for the
API use`, или 403 `PERMISSION_DENIED`), патч это не исправит — CLI честно покажет
серверную ошибку. На проверенном аккаунте таких отказов нет: ответы приходят.

У `agy` нет настройки вида «region/eligibility» в `settings.json`: строки
`"region"`, `"location"`, `detected_location` относятся к телеметрии и
Vertex-маршрутизации, а не к гейту. Поэтому исправление — адресная правка
машинного кода.

---

## 2. Что делает патч

Две точечные замены в исполняемых сегментах ELF (x86-64):

**CLI, `handleAuthResult`:**

```asm
; было
test rcx, rcx
je   ...
cmp  byte ptr [rcx+8], 0     ; hasValidAuth
jne  eligible
; стало
test rcx, rcx
je   ...
test rcx, rcx                ; ZF=0, rcx здесь не ноль
nop
jne  eligible                ; всегда уходит в "eligible"
```

**Hub / IDE, `PersonalAuthValidator.Validate`:**

```asm
; было
cmp byte ptr [rax+8], 0
je  ...
; стало
mov byte ptr [rax+8], 1      ; hasValidAuth = true
nop
nop
```

Меняются только эти байты. TLS, сертификаты, сетевые настройки, токены и
учётные данные не затрагиваются. Программа не ходит в сеть.

---

## 3. Установка и использование

```bash
cd ~/Проекты/antigravity-region-fix

./agy-region-fix status      # версия, архитектура, состояние сигнатур, бэкап
./agy-region-fix patch       # применить (создаёт проверенный бэкап)
./agy-region-fix verify      # убедиться, что патч на месте
./agy-region-fix test        # реальный запрос: agy -p "Reply with exactly OK"
./agy-region-fix doctor      # проверить каждую модель живым запросом
./agy-region-fix restore     # вернуть оригинальный бинарник
./agy-region-fix autopatch install   # патчить самому после каждого обновления
```

Полезное:

```bash
./agy-region-fix doctor      # какие модели отвечают (ничего не меняет)
./agy-region-fix --dry-run patch          # показать смещения и хэши, ничего не писать
./agy-region-fix --path /opt/agy patch    # явный путь
./agy-region-fix --all patch              # + бэкенды приложений (App и IDE)
./agy-region-fix --app patch              # только приложения Antigravity App/IDE
./agy-region-fix backups                  # список резервных копий
./agy-region-fix prune --keep 1           # удалить старые копии (каждая ~200 МБ)
./agy-region-fix gates                    # известные сигнатуры
./agy-region-fix autopatch status          # как работает автопатч
./agy-region-fix autopatch run             # одна проверка сейчас (без systemd)
./agy-region-fix autopatch uninstall       # выключить автопатч
```

### Antigravity App и IDE

`--app` добавляет к целям:

* `~/.local/opt/antigravity-app/Antigravity-x64/resources/bin/language_server`
  — Go-бэкенд приложения «Google Antigravity App» (версия берётся из
  `resources/app.asar`, сейчас 2.29.0). Патчится гейт `hasValidAuth`
  (`PersonalAuthValidator.Validate`).
* `~/.gemini/bin/agy` — hub-бэкенд, который использует расширение `agy`
  в Antigravity IDE (1.5.2). Патчатся оба гейта.

Electron-бинарник `antigravity` и `antigravity-ide` не трогаются: в них нет
Go-гейта, вся проверка живёт в language_server/hub-бэкенде.

После обновления приложения (автообновление или переустановка) достаточно снова
выполнить `./agy-region-fix --app patch`.

Коды возврата: `0` — успех, `1` — ошибка проверки/теста, `2` — сигнатуры не
найдены или неоднозначны (запись не выполнялась), `3` — бинарник запущен.

### 3.1 macOS

Патчер понимает Mach-O: thin (x86_64 или arm64) и universal (fat) с двумя
слайсами. Каждый слайс сканируется сигнатурами своей архитектуры, поэтому
universal-бинарник патчится целиком за один запуск.

```bash
cd ~/antigravity-region-fix      # или любой каталог, куда скопирован проект
./agy-region-fix status          # покажет контейнер: macho / universal(x64+arm64)
./agy-region-fix patch
./agy-region-fix verify
./agy-region-fix restore
```

Пути по умолчанию: `agy` из `PATH`, `~/.local/bin/agy`, `/usr/local/bin/agy`,
`/opt/homebrew/bin/agy`. Приложение — `/Applications/Antigravity.app/Contents/Resources/bin/language_server`
(и `~/Applications/...`), включается флагом `--app` или `--all`.

**Разрешение macOS (обязательно для `.app`).** macOS не даёт терминалу менять
файлы внутри чужих приложений — это защита TCC, а не права Unix. Пока
разрешение не выдано, запись внутрь `Antigravity.app` физически невозможна
(«Operation not permitted»), и никакой `sudo` этого не обходит.

Перед первым `--app patch`:

1. Меню Apple → **Системные настройки** → **Конфиденциальность и безопасность**
   → прокрутить до **Управление приложениями** (App Management).
2. Нажать **«+»** → **Программы** → **Утилиты** → **Terminal** (или iTerm) →
   **Открыть**.
3. Включить переключатель. macOS может предупредить, что терминал будет
   закрыт, — согласиться (сеанс перезапустится).
4. Открыть терминал заново и повторить `./agy-region-fix --app patch`.

Проверить, что разрешение есть, можно так:

```bash
# должно пройти без "Operation not permitted"
touch "/Applications/Antigravity.app/Contents/Resources/bin/.write-test" && \
  rm "/Applications/Antigravity.app/Contents/Resources/bin/.write-test"
```

Для standalone CLI вне `.app` (например `~/.local/bin/agy`) это разрешение не
требуется.

**Подпись кода.** Правка байтов ломает исходную подпись Google, а на Apple
Silicon ядро не запускает неподписанный код. Порядок, который применяет патчер
(проверен по upstream RendeRR/QNIX-патчеру):

1. **Снапшот подписи.** Перед первой правкой внутри `.app` сохраняется
   оригинальная подпись в `<App>.app.agysignbak`: главный исполняемый файл,
   `Contents/_CodeSignature/*`, `Contents/CodeResources` + манифест с sha256.
   `restore` возвращает их вместе с оригинальными байтами, поэтому приложение
   остаётся с подписью Google.
2. **Почему нельзя подписывать только изменённый файл.** Electron-приложение
   состоит из Helper'ов (`Contents/Frameworks/* Helper.app`), подписанных
   Google со своим Team ID и Hardened Runtime. Если изменённый
   `language_server` подписать ad-hoc, а Helper'ы оставить как есть, то при
   загрузке `Electron Framework.framework` ядро убьёт каждый Helper с
   «mapping process and mapped file (non-platform) have different Team IDs»,
   и приложение упадёт на старте. Entitlement
   `disable-library-validation`, добавленный только главному файлу, Helper'ам
   не помогает.
3. **Равномерная переподпись.** Поэтому для `.app` патчер выполняет
   `codesign --force --deep --sign - --options=0 <App>`: весь бандл, включая
   Helper'ы, подписывается ad-hoc, а `--options=0` снимает Hardened Runtime и
   вместе с ним Library Validation у всех процессов. После этого фреймворк
   грузится независимо от Team ID.
4. **Проверка** `codesign --verify --deep --strict`; при ошибке патчер
   откатывает байты и подпись из бэкапа.
5. **Quarantine** снимается (`xattr -dr com.apple.quarantine`), иначе
   Gatekeeper может заблокировать запуск.

Для standalone CLI (вне `.app`) подписывается только сам бинарник, с
сохранением метаданных. Отключить подпись можно флагом `--no-resign`, тогда
обновить её придётся вручную:

```bash
# CLI
codesign --force --sign - --timestamp=none ~/.local/bin/agy
# приложение (если запускали с --no-resign)
codesign --force --deep --sign - --options=0 /Applications/Antigravity.app
```

Флаг `--macos-disable-library-validation` сохранён для совместимости, но
больше не нужен.

Цена: нотаризация Google после патча больше не действует — система не
подтверждает, что код пришёл от Google. Это неизбежно при изменении
подписанного бинарника.

**Проверка сигнатур на Mac.** arm64-сигнатуры взяты из upstream, а затем
подтверждены на официальной Windows arm64-сборке 1.5.17 (PE). На реальном
Apple Silicon запуск всё ещё не проверялся. Первый запуск на Mac:

```bash
./agy-region-fix --path /Applications/Antigravity.app/Contents/Resources/bin/language_server status
```

Если для слайса написано `absent` — код гейта в этой сборке отличается (или не
совпал контекст: перед arm64-гейтом CLI обязаны стоять `cbnz x1` и `cbz x0`;
патчер проверяет их, чтобы не зацепить похожие байты). Патчер в этом случае
ничего не запишет (код 2). Пришлите вывод `status` и `uname -m` — сигнатуры
поправлю.

iOS/macOS-специфика: `agy` для macOS ставится тем же установщиком, автообновление
перезаписывает бинарник и снимает патч так же, как на Linux; после обновления
повторите `./agy-region-fix patch`.

### 3.2 Windows

Поддерживается PE32+ (x64 и arm64). Нужен только Python 3.8+ с python.org,
без сторонних пакетов:

```powershell
cd путь\к\antigravity_patcher

py agy_region_fix.py status     # версия, архитектура, контейнер, состояние
py agy_region_fix.py patch
py agy_region_fix.py verify
py agy_region_fix.py restore
```

Если `agy` не находится в PATH, укажите путь явно (`.exe` обязателен):

```powershell
py agy_region_fix.py --path "$env:USERPROFILE\.local\bin\agy.exe" status
py agy_region_fix.py --path "C:\Tools\Antigravity\antigravity.exe" patch
```

Что проверено на официальной сборке 1.5.17 (`agy_cli_windows_x64.zip` и
`agy_cli_windows_arm64.zip` с GitHub Releases):

* обе сигнатуры (`cli`, `hub`) находятся **ровно по одному разу** и в x64,
  и в arm64;
* патч меняет те же 4 и 6 байт, после чего `verify` видит `patched`;
* версия определяется запуском `antigravity.exe --version` (на Windows это
  работает; при осмотре PE-файла с Linux версия будет `unknown`).

Чего в Windows-сборке нет и что важно знать:

* **Файл блокируется, пока `agy` запущен.** Windows не даст заменить
  работающий `.exe`: патчер вернёт понятную ошибку «файл занят». Закройте CLI
  и повторите (автопатч сам повторит позже).
* **Подпись Google перестаёт действовать.** Официальный `.exe` подписан
  Authenticode; после правки подпись невалидна. Windows запускает такой файл,
  но SmartScreen/Defender могут показать предупреждение о неизвестном
  издателе. Это неизбежно: переподписать без сертификата Google нельзя.
* **Бэкап** — тот же `.orig` + JSON в `%LOCALAPPDATA%\antigravity-region-fix\backups\`.
* После автообновления CLI файл заменяется целиком, патч исчезает — как и на
  других платформах, см. раздел 5.

Автопатч на Windows ставится задачей Планировщика (см. 5.1):

```powershell
py agy_region_fix.py autopatch install
py agy_region_fix.py autopatch status
py agy_region_fix.py autopatch uninstall
```

---

## 4. Гарантии безопасности

* **Резервная копия** кладётся в
  `~/.local/share/antigravity-region-fix/backups/agy-<версия>-<sha12>.orig`
  вместе с JSON-манифестом (sha256, размер, версия, архитектура, дата).
* **Проверка сигнатур** — только в исполняемых PT_LOAD-сегментах ELF,
  секциях Mach-O с `VM_PROT_EXECUTE` и PE-секциях с `IMAGE_SCN_MEM_EXECUTE`. Патч
  применяется, если сигнатура найдена **ровно один раз**. Ноль, два и более
  совпадений, а также смешанное состояние «частично пропатчено» → отказ без записи.
* **Защита от повторного применения** — повторный `patch` сообщает
  «уже пропатчено» и ничего не пишет.
* **Атомарная запись** — временный файл в том же каталоге, `fsync`, `os.replace`,
  сохранение прав. После записи хэш и состояние гейтов перепроверяются; при
  расхождении автоматически восстанавливается оригинал.
* **Проверка бэкапа** — `restore` принимает только копию, чей sha256 совпадает с
  манифестом, и которая сама не содержит патча.
* **Запущенный процесс** — патч/откат отказываются работать, пока `agy` запущен
  (обход только явным `--force`).
* Никаких токенов в логах, никакой сети, никакой подмены TLS.

---

## 5. Обновления CLI и автопатч

`agy` обновляется сам. Обновление скачивает новый бинарник целиком и
подменяет файл — патч при этом исчезает, и CLI снова показывает экран
«location is not supported». Это ожидаемо: патч живёт в байтах бинарника.

### 5.1 Автопатч (включён)

Патчер умеет переприменять себя после каждого обновления — через user-юниты
systemd:

```bash
./agy-region-fix autopatch install     # включить (по умолчанию только CLI)
./agy-region-fix --all autopatch install   # + бэкенды App/IDE
./agy-region-fix autopatch status      # юниты, цели, последний запуск, журнал
./agy-region-fix autopatch uninstall   # выключить (патч в файле остаётся)
```

Как это устроено:

* `antigravity-region-fix.path` — `PathChanged=` + `PathModified=` на каждый
  целевой файл. Срабатывает и на атомарную подмену (`rename`), и на запись на
  месте, то есть на любой способ, которым апдейтер ставит новый бинарник.
* `antigravity-region-fix.service` — oneshot, запускает
  `agy-region-fix autopatch run`.
* `antigravity-region-fix.timer` — страховка: проверка через 2 минуты после
  входа и далее каждые 10 минут (`--interval` меняет период, `0` — только по
  событию). Нужна, потому что событие inotify можно пропустить, если файл
  пишется в момент, когда сервис уже занят.

Что делает `autopatch run`:

1. ждёт, пока размер/mtime/inode файла перестанут меняться (апдейтер пишет
   250+ МБ, патчить недописанный файл нельзя);
2. если версия уже пропатчена — молча выходит;
3. если оригинал — патчит с `--force` (файл подменяется атомарно, запущенный
   процесс продолжает работать со старой копией inode), проверяет хэш и
   сигнатуры, оставляет максимум 3 резервные копии;
4. если сигнатуры не найдены или состояние смешанное — **ничего не пишет**,
   один раз пишет в журнал и показывает уведомление на десктопе: нужны свежие
   сигнатуры в проекте. Повторные запуски с тем же хэшем не спамят.

Журнал: `~/.local/share/antigravity-region-fix/autopatch.log` (ротация на
512 КБ). Состояние: `autopatch.json` рядом. Запуск от systemd виден ещё и в
`journalctl --user -u antigravity-region-fix.service`.

Если хочется совсем без systemd — тот же `autopatch run` можно вызывать из
cron (`*/10 * * * *`) или из своей обёртки; разницы в поведении нет.

**Windows:** `autopatch install` создаёт задачу Планировщика
`AntigravityRegionFix`, которая каждые 10 минут (или `--interval N`) запускает
`autopatch run` через сгенерированный `autopatch-run.cmd`. Проверить:
`schtasks /Query /TN AntigravityRegionFix`. Событийного inotify там нет, так
что периодический запуск — основной механизм; патч применяется в течение
10 минут после обновления, а если CLI в этот момент запущен — при следующем
запуске задачи, когда файл уже свободен.

**macOS:** systemd там нет, поэтому `autopatch install` рассчитан на Linux.
На Mac используйте тот же `autopatch run` из `launchd` (StartInterval 600)
или из cron:

```bash
# crontab -e
*/10 * * * * /путь/к/agy-region-fix autopatch run
```

Учтите, что после патча внутри `.app` на macOS ещё и переподписывается бандл
(`codesign`), поэтому автопатч приложения требует, чтобы Terminal/launchd
имел доступ к `codesign` и записи в бандл.

### 5.2 Вручную

```bash
./agy-region-fix status      # увидит новую версию и состояние "original"
./agy-region-fix patch       # создаст бэкап новой версии и пропатчит её
```

Сигнатуры не привязаны к абсолютным смещениям, поэтому работают на всех
проверенных сборках: смещения меняются от сборки к сборке (1.5.13 —
`cli @ 0x9d09c09`; 1.5.16 — `cli @ 0x9e2a889`, `hub @ 0x97234aa`), а
сигнатуры ищутся по байтам. Если в новой версии код гейта перепишут,
патчер откажется писать и вернёт код `2` (автопатч в этом случае пришлёт
уведомление) — тогда нужно обновить сигнатуры в `GATES`.

---

## 6. Результаты проверки (реальные)

| Шаг | Команда | Результат |
|---|---|---|
| Исходное состояние | `agy -p "Reply with exactly OK"` | ошибка eligibility, exit 1 |
| Патч | `./agy-region-fix patch` | cli @ 0x9d09c12, hub @ 0x9639eea |
| Запуск | `agy --version` | `1.5.14` |
| Модели | `agy models` | Gemini 3.8 Flash, Claude Sonnet 4.6, Claude Opus 4.6, GPT-OSS 120B |
| Запрос 1 | `agy -p "Reply with exactly OK"` | `OK`, exit 0 |
| Запрос 2 | `agy -p "Compute 17*23..."` | `391`, exit 0 |
| Запрос 3 | `agy -p "почему небо синее?"` | развёрнутый ответ по-русски, exit 0 |
| Повторный патч | `./agy-region-fix patch` | «уже пропатчено», exit 0 |
| Откат | `./agy-region-fix restore` | sha256 оригинала совпал |
| После отката | `agy -p ...` | снова ошибка eligibility, exit 1 |

### Antigravity App 2.29.0 (language_server)

| Шаг | Действие | Результат |
|---|---|---|
| Оригинал | запуск приложения | экран «Welcome to Antigravity / Continue with Google», сессия не принимается |
| Патч | `./agy-region-fix --app patch` | hub @ 0x770848a |
| Запуск | приложение | «Hi <имя>», авторизация подхватилась сама |
| Модели | список моделей в UI | Gemini 3.8 Flash (High/Medium/Low), Claude Sonnet 4.6, Claude Opus 4.6, GPT-OSS 120B |
| Запрос 1 | «Reply with exactly OK» | `OK` |
| Запрос 2 | «Compute 17*23…» | `391` |

Проверка выполнялась через CDP самого приложения (без ручных кликов),
ответы получены от модели, а не из кэша.

Авторизация не сбрасывалась: использован существующий токен из keyring,
повторного входа не требовалось.

---

## 7. Файлы

```
antigravity_patcher/
├── agy-region-fix              # Bash-launcher
├── agy_region_fix.py           # патчер (stdlib Python 3.8+)
├── pyproject.toml              # установка через pipx/pip
├── Makefile                    # test / install / uninstall / status
├── LICENSE                     # MIT
├── NOTICE                      # атрибуция upstream
├── README.md
├── ci/github-actions-tests.yml # готовый CI (включается вручную, см. шапку файла)
└── tests/test_patcher.py       # 42 юнит-теста

~/.local/share/antigravity-region-fix/
├── backups/<имя>-<версия>-<sha12>.orig (+ .json)
├── autopatch-run.sh    # обёртка для systemd (генерируется)
├── autopatch-run.cmd   # обёртка для Планировщика Windows
├── autopatch.json      # цели и результат последнего запуска
└── autopatch.log       # журнал автопатча

~/.config/systemd/user/
├── antigravity-region-fix.service
├── antigravity-region-fix.path
└── antigravity-region-fix.timer
```

Запуск тестов: `make test` (или `python3 tests/test_patcher.py`).

---

## 8. Честный вывод

На проверенном аккаунте ограничение действительно **клиентское**: сервер сообщает
признак региона в `loadCodeAssist`, но модели и генерация для аккаунта доступны.
Патч снимает локальный гейт, и CLI получает реальные ответы моделей через штатную
инфраструктуру Google — без VPN, прокси и смены региона.

Если на другом аккаунте Google отклонит уже сам модельный запрос, это будет
видно как серверная ошибка 400/403; в таком случае ограничение находится на
стороне сервера и локальным патчем не решается.

---

## 9. Если что-то не работает

Начните с трёх команд — они объясняют большинство случаев:

```bash
cd ~/Проекты/antigravity-region-fix      # или каталог клона
./agy-region-fix status
agy --version; uname -m
tail -40 ~/.gemini/antigravity-cli/log/cli-*.log
```

`status` показывает путь, версию, архитектуру, контейнер (elf/macho), sha256,
состояние каждого гейта и наличие бэкапа.

### 9.1 Быстрая таблица

| Симптом | Причина | Решение |
|---|---|---|
| `agy: command not found` | другой PATH / не та установка | `which -a agy`, затем `./agy-region-fix --path /полный/путь/agy patch` |
| `patch` вернул **2**, «ни одна сигнатура не найдена» | новая версия CLI с другим кодом | ничего не записано; пришлите `status` + `agy --version` + `uname -m` |
| `patch` вернул **2**, «ambiguous/mixed» | остатки прошлого патча или нестандартная сборка | `./agy-region-fix restore`, затем `patch`; если повтор — переустановите `agy` |
| `patch` вернул **3** | `agy` запущен | закройте CLI/IDE/приложение, повторите |
| «нет прав на запись» | файл принадлежит root | `sudo ./agy-region-fix patch` или исправьте владельца |
| Windows: «файл занят», запись не идёт | запущен `agy.exe`, файл заблокирован ОС | закройте CLI; автопатч повторит сам |
| Windows: SmartScreen «неизвестный издатель» | подпись Google аннулирована патчем | это ожидаемо; запускайте файл, который сами пропатчили |
| Windows: `status` показывает версию `unknown` | PE осматривается с Linux или имя файла не `agy.exe`/`antigravity.exe` | на Windows версия берётся из `--version`; для копии это нормально |
| Патч применён, но снова ошибка региона | пропатчен не тот файл | `which agy` и `./agy-region-fix status`; сверьте путь |
| После обновления CLI всё сломалось | автообновление вернуло оригинал | есть автопатч: `autopatch status`; иначе `./agy-region-fix verify` → `patch` |
| Автопатч не сработал | юнит не включён / файл вне списка целей | `./agy-region-fix autopatch status`, затем `autopatch install` заново |
| Уведомление «нужны свежие сигнатуры» | новая версия с другим кодом гейта | ничего не записано; пришлите `status` + `agy --version` |
| `400 FAILED_PRECONDITION`, «User location is not supported for the API use» **только на Gemini** | сервер режет это семейство по IP, остальные работают | `./agy-region-fix doctor` покажет, что отвечает; модель по умолчанию не меняется |
| `400 FAILED_PRECONDITION` на всех моделях | **серверный** отказ по IP/аккаунту | локальным патчем не решается |
| `403 PERMISSION_DENIED` | **серверные** права/регион аккаунта | локальным патчем не решается |
| `429` / quota exceeded | лимиты тарифа | подождать/сменить модель |
| `context deadline exceeded` | сеть, DNS, IPv6 | см. 9.5 |
| «You are not signed in» / просит войти | истекла сессия | войдите заново в `agy`; см. 9.4 |
| Приложение показывает Welcome, хотя `agy` работает | не пропатчен `language_server` | `./agy-region-fix --app patch` |
| macOS: «Operation not permitted» / «не удаётся сохранить файл» | нет разрешения **Управление приложениями** | выдать Terminal доступ в Privacy & Security → App Management; см. 3.1 |
| macOS: «приложение повреждено» | подпись после правки | `restore`, затем `patch` с корректной подписью; см. 9.6 |
| macOS: приложение падает на старте с «different Team IDs» | Helper'ы остались с подписью Google | подпишите весь бандл: `codesign --force --deep --sign - --options=0 <App>`; см. 9.6 |
| macOS: `absent` для arm64 | другая сборка/контекст | пришлите `status` и `uname -m` |

### 9.2 Коды возврата и что они значат

| Код | Значение | Файл изменён? |
|---|---|---|
| `0` | успех (в т.ч. «уже пропатчено») | да / уже был |
| `1` | не прошла проверка `verify` или тестовый запрос | да |
| `2` | сигнатуры не найдены/неоднозначны, бэкап повреждён | **нет** |
| `3` | бинарник запущен | нет |

`patch` пишет только при однозначном совпадении. Если сигнатура найдена 0 раз,
2+ раза или в смешанном состоянии (часть уже пропатчена) — запись отменяется,
оригинал остаётся нетронутым.

Проверить, что именно нашлось, не записывая:

```bash
./agy-region-fix --dry-run patch
```

### 9.3 Патч на месте, но CLI всё равно отказывает

1. Убедитесь, что пропатчен тот файл, который запускается:

   ```bash
   which -a agy
   ./agy-region-fix --path "$(which agy)" status
   ```

   В выводе должно быть `состояние: пропатчен` и `patched cli` (и `patched hub`,
   если есть).

2. Посмотрите, что говорит сервер, а не клиент:

   ```bash
   tail -60 ~/.gemini/antigravity-cli/log/cli-*.log | grep -Ei 'ineligible|eligib|PERMISSION_DENIED|FAILED_PRECONDITION|403|400'
   ```

   * `Account ineligible: ... not currently available in your location` —
     это ответ `loadCodeAssist`; клиентский гейт снят, запрос уходит дальше.
   * Если **после** этого появляется `403 PERMISSION_DENIED` или
     `400 FAILED_PRECONDITION` на `streamGenerateContent` — ограничение уже
     серверное. Патч его не обходит, и это не лечится клиентом.
     Если `400` приходит только на Gemini, а Claude/GPT-OSS отвечают,
     это блокировка конкретного семейства по IP: `./agy-region-fix doctor`
     покажет, что работает. Модель по умолчанию при этом менять не нужно —
     достаточно запускать нужную явно: `agy --model claude-sonnet-4-6 -p "..."`.
   * Если ошибок нет и приходит ответ модели — всё работает.

3. Проверьте, не обновился ли бинарник между патчем и запуском:

   ```bash
   ./agy-region-fix verify; agy --version
   ```

   Автообновление перезаписывает файл. После каждого обновления — `patch`.

4. Если `agy` запускается из другого места (обёртка, `.desktop`, IDE),
   проверьте все копии:

   ```bash
   ./agy-region-fix --all status
   ls -l ~/.local/bin/agy ~/.gemini/bin/agy
   ```

### 9.4 Авторизация, keyring, токены

* Токен хранится в системном keyring. Если keyring заблокирован (GNOME
  Keyring/oo7), `agy` не сможет его прочитать: разблокируйте связку ключей и
  повторите запуск.
* Повторный вход: запустите `agy` без `-p` и пройдите вход в браузере. Это
  безопаснее, чем удалять файлы авторизации.
* `~/.gemini/oauth_creds.json` может содержать просроченный `access_token` —
  это нормально, клиент обновляет его по `refresh_token`. Не удаляйте файл без
  необходимости.
* Ни патчер, ни его логи не печатают токены. Если вы присылаете лог для
  диагностики, убедитесь, что в нём нет заголовков `Authorization`.

### 9.5 Сеть, DNS, прокси

Патч не меняет сетевые настройки; если проблема сетевая, он не поможет:

```bash
env | grep -i proxy                 # прокси не должен быть обязательным
getent hosts daily-cloudcode-pa.googleapis.com
curl -sS -o /dev/null -w '%{http_code}\n' https://daily-cloudcode-pa.googleapis.com
curl -sS -o /dev/null -w '%{http_code}\n' https://www.googleapis.com
```

* `000` или таймаут — DNS/файрвол/провайдер.
* Долгие ответы (10+ секунд) часто из-за IPv6: сравните
  `curl -4` и `curl -6`. При проблеме с IPv6 помогает приоритет IPv4 на уровне
  приложения/сети, но это уже изменение системных настроек — делайте осознанно.
* Корпоративный прокси/MITM ломает TLS: патч здесь ни при чём, и отключать
  проверку сертификатов не нужно и не следует.

### 9.6 macOS

```bash
# что видит система
codesign -d --verbose=4 /Applications/Antigravity.app 2>&1 | head -20
codesign --verify --deep --strict --verbose=2 /Applications/Antigravity.app
spctl -a -vv /Applications/Antigravity.app
xattr -l /Applications/Antigravity.app
```

* **«Operation not permitted» при записи в `.app`.** Это TCC/App Management, а
  не обычные права файла: `sudo` не помогает. Выдайте терминалу разрешение
  «Управление приложениями» (Системные настройки → Конфиденциальность и
  безопасность → App Management → «+» → Программы → Утилиты → Terminal),
  согласитесь на перезапуск терминала и повторите `--app patch`. Подробно —
  в разделе 3.1.

* **Приложение падает на старте: «different Team IDs» / «Library not
  loaded: @rpath/Electron Framework.framework».** Так бывает, если бандл
  подписан частично: изменённый `language_server` — ad-hoc, Helper'ы —
  с подписью Google. Нужна равномерная переподпись всего бандла без
  Hardened Runtime (патчер 1.2.1 делает это сам):

  ```bash
  codesign --force --deep --sign - --options=0 /Applications/Antigravity.app
  xattr -dr com.apple.quarantine /Applications/Antigravity.app
  codesign --verify --deep --strict /Applications/Antigravity.app
  ```

* **«Приложение повреждено» / не запускается.** Верните оригинал и подпись:

  ```bash
  ./agy-region-fix --app restore
  ```

  Затем при необходимости пропатчьте заново. Снапшот оригинальной подписи
  лежит рядом: `<App>.app.agysignbak`.

* **Нужна ручная подпись** (`--no-resign`):

  ```bash
  codesign --force --sign - --timestamp=none --preserve-metadata=identifier,entitlements,flags,runtime <файл>
  codesign --force --deep --sign - --timestamp=none /Applications/Antigravity.app
  codesign --verify --deep --strict /Applications/Antigravity.app
  ```

* **Gatekeeper/quarantine.** После правки снимите карантин:

  ```bash
  xattr -dr com.apple.quarantine /Applications/Antigravity.app
  ```

  Первый запуск — правый клик → «Открыть».

* **`absent` для arm64.** Сигнатура arm64 требует контекста `cbnz x1; cbz x0`.
  Если его нет, патчер не пишет. Пришлите `status` и `uname -m`.

* **Универсальный бинарник.** Патчатся оба слайса; в `status` будет
  `universal(x64+arm64)`. Если один слайс не найден — будет `absent` только у
  него, второй пропатчится.

### 9.7 Приложение Antigravity и IDE

* Пути: `~/.local/opt/antigravity-app/.../resources/bin/language_server`
  (Linux), `/Applications/Antigravity.app/Contents/Resources/bin/language_server`
  (macOS).
* Пропатчить: `./agy-region-fix --app patch`; проверить:
  `./agy-region-fix --app verify`.
* `Error Loading Models: ... context deadline exceeded` — сеть, не патч
  (см. 9.5). После исправления сети перезагрузите окно.
* Экран «Welcome to Antigravity / Continue with Google» при рабочем `agy` —
  не пропатчен `language_server` либо запущена старая копия приложения.
* IDE использует `~/.gemini/bin/agy` как бэкенд; он входит в `--app`/`--all`.
* Автообновление приложения и CLI возвращает оригиналы — повторите `patch`.

### 9.8 Откат и восстановление

```bash
./agy-region-fix restore                  # последняя подходящая копия
./agy-region-fix restore --version 1.5.14 # копия конкретной версии
./agy-region-fix restore --from ~/.local/share/antigravity-region-fix/backups/agy-....orig
./agy-region-fix backups                  # что вообще есть
```

`restore` проверяет, что копия не повреждена и сама не содержит патча; при
несовпадении sha256 откажется писать.

Если бэкапа нет (например, проект скопирован на другую машину): переустановите
`agy` официальным установщиком — он вернёт оригинальный бинарник. Резервные
копии хранятся локально и в репозиторий не попадают.

Убрать саму утилиту, не трогая Antigravity:

```bash
make uninstall
rm -rf ~/.local/share/antigravity-region-fix   # заодно удалит бэкапы
```

### 9.9 Что прислать, если нужна помощь

Достаточно этого (без токенов и cookie):

```bash
./agy-region-fix status
./agy-region-fix gates
agy --version; uname -a
sha256sum "$(which agy)"
tail -50 ~/.gemini/antigravity-cli/log/cli-*.log
```

Для macOS добавьте `uname -m` и вывод `codesign -d --verbose=4` по бандлу.

### 9.10 Чего патч не делает

* Не выдаёт платные модели и не меняет тариф — это решает сервер.
* Не обходит серверный отказ `400/403` по региону аккаунта.
* Не «включает» Gemini Web и AI Studio: у них нет клиентского гейта, отказ
  приходит с сервера.
* Не отключает TLS, не подменяет DNS, не настраивает прокси, не трогает токены.

## 10. Источники и совместимость

* Сигнатуры гейтов и arm64-контекст (`cbnz x1; cbz x0`) сверены с
  [RendeRR/antigravity-patcher](https://github.com/RendeRR/antigravity-patcher)
  (MIT), который в свою очередь основан на
  [QNIX-Dev/eligibility-antigravity-patcher](https://github.com/QNIX-Dev/eligibility-antigravity-patcher).
* Логика macOS-подписи (снапшот подписи бандла, равномерная ad-hoc подпись
  всего бандла с `--options=0`, снятие quarantine) сверена с отчётом о реальном
  крэше `different Team IDs` на macOS 26 arm64; реализация и все проверки —
  в этом проекте.
* Официальное: [google-antigravity/antigravity-cli](https://github.com/google-antigravity/antigravity-cli),
  [antigravity.google/docs](https://antigravity.google/docs/).
* Версии, на которых сверены сигнатуры: CLI 1.5.13–1.5.17 (Linux x86-64),
  1.5.17 (Windows PE x64 и arm64);
  бэкенд IDE 1.5.2; приложение 2.29.0 (language_server).
