# ТОЧКА ВОЗОБНОВЛЕНИЯ · 26.10.2026, ~15:10 MSK

Ноутбук закрывается. Ниже всё, что нужно, чтобы продолжить ровно с этого места,
не переспрашивая контекст.

## Где мы остановились

Работа над **reziume** (`C:\Users\Artur\projects\reziume-v2`) и параллельно над
универсальным скиллом безопасности (`C:\Users\Artur\projects\agent-security-audit`).

### Сделано и проверено

1. **Магнитный движок** в проде: `static/js/magnet.js`, ADR 0002, живая проверка
   `scripts/check_live.sh`. Коммиты `aff1216`, `8b47804`, `d8f8dfb`.
2. **Редакционный редизайн** в проде: терракота `#B4372A`, ноль теней, скругления
   2–3 px, 8 токенов типографики, услуги строками с индексом. ADR 0003, коммиты
   `cd9a68c`, `b58182f`, `889f228`. dsh выполнил за 734 с, гейт зелёный, дsh
   перезапускал выкладку и она прошла (`verification.ok = true`).
3. **Исследование угроз** (3 субагента, 1110 с): файлы в
   `C:\Users\Artur\AppData\Local\hermes\cache\scratch\sec\`:
   - `01-threats.md` (65 КБ, 110 ссылок, 25 CVE, 4 ИИ-кампании),
   - `02-django-vps-audit.md` (50 КБ, 70 строк «риск → команда → закрытие»),
   - `03-tooling.md` (49 КБ, проверенные инструменты и MCP).
   Сводка закоммичена в `docs/SECURITY.md` (коммит `90d16af`).
4. **Мои личные проверки** (не по пересказу): gunicorn 23.0.0 в lock (уязвимый
   диапазон smuggling), `.env` не исключён в `deploy.sh`, уведомления в Telegram без
   `html.escape` при `parse_mode=HTML`, `pip-audit` чист, `bandit` 3 замечания,
   `check --deploy` локально даёт 6 предупреждений из-за dev `.env` (на проде
   большинство уже закрыто `settings.py:155-161`), HSTS выключен намеренно.
5. **Тикет 023 «диагностика безопасности» выполнен dsh** (368 с, `verification.ok = true`,
   код не менялся). Отчёт: `docs/security/AUDIT-2026-10-26.md` (28 КБ, 9 разделов,
   таблица оценок). Ключевые находки с хоста:
   - **P1: PostgreSQL опубликован на `0.0.0.0:5432`**, UFW `ALLOW IN Anywhere`
     (docker `postgres`). База открыта в интернет.
   - **P1: `/opt/reziume/.env` лежит на проде, права 644**, содержит
     `TELEGRAM_BOT_TOKEN`, sha256 совпал с локальным файлом. Утечка деплоя
     подтверждена фактом, а не гипотезой.
   - **P1: gunicorn 23.0.0** на хосте (pre-CVE smuggling).
   - **P2: n8n (`0.0.0.0:5678`) и Flowise (`0.0.0.0:3000`) опубликованы наружу**,
     UFW разрешает. Это ровно тот «агентский контур», о котором шла речь в
     исследовании угроз: открытые панели агентов ищутся сканерами.
   - P2: Caddy 2.11.4 отстаёт от 2.11.6+, HSTS выключен, HTML-инъекция в
     уведомлениях, нет лимитов частоты на заявки/загрузку/OAuth.
   Отчёт **не закоммичен** (untracked `docs/security/`) – это первое, что надо
   сделать на возобновлении.
6. **Пакет скилла** `agent-security-audit` создан и частично проверен:
   `SKILL.md` (procedure 8 шагов, правила, ловушки), `README.md` (установка в Claude
   Code, Cursor, Codex, Hermes), `references/findings-catalog.md` (12 классов
   находок), `references/threats-2026-q4.md`, `references/tooling.md`,
   `scripts/audit.py`, `scripts/scan-web.sh`, `scripts/scan-host.sh`.

### Что осталось недоделанным в скилле

- **`audit.py` проверен, точность в норме.** Финальный прогон на reziume: 4 находки –
  P1 «Деплой-скрипт не исключает .env» (`scripts/deploy.sh`, сработал как задумано
  после правки регекспа по `--exclude`), P3 `urlopen` в `apps/accounts/oauth.py:60`,
  и две info (pip-audit чист; env-файлы на диске). Ложные срабатывания на тестах и на
  литеральном `execute("SELECT 1")` устранены.
- **Прогнать `scan-web.sh`** на `https://reziume.korobkai.ru` (проверить работу
  HSTS/заголовков/TLS и отсутствие утечек файлов).
- **Прогнать `scan-host.sh`** на `vps` с юнитом `reziume.service` (sshd, порты, ufw,
  fail2ban, права env, `noexec` у media).
- **Написать пост для Telegram-канала** по скиллу. Голос – `@korobkaAI`, скилл
  `telegram-channel-ghostwriting`: медиана ~1080 знаков, диапазон 1100–1500, хук в
  первом абзаце, две версии (markdown для редактора + plain `.txt`).
- **`git init` + commit + инструкция публикации** пакета на GitHub
  (`gh repo create`). Пуш не делал – это внешнее действие, нужно слово владельца.
- Опционально: `LICENSE` (MIT) в пакете, `examples/` с образцом отчёта.

### Что дальше по безопасности reziume (план согласован)

- **024** – быстрые закрытия: gunicorn → ≥26.2.2, `--exclude=.env` в деплое,
  `html.escape` в уведомлениях, HSTS 300 с → год.
- **025** – лимиты частоты на заявку/загрузку/вход; привязка заказов по одноразовому
  коду вместо строки контакта; `Content-Type` при скачивании всегда octet-stream.
- Выкладка – только после показа находок владельцу.

## Точные команды для возобновления

```bash
# 1. состояние репозитория
cd /c/Users/Artur/projects/reziume-v2 && git status --short && git log --oneline -6

# 2. итог прерванного рана
cat report.json | head -40; ls -la docs/security/ 2>/dev/null

# 3. если ран 023 не завершён – перезапустить (он только читает)
.venv/Scripts/python.exe C:/Users/Artur/AppData/Local/hermes/tools/dsh-acp/dsh_acp.py run \
  --cwd C:/Users/Artur/projects/reziume-v2 --prompt-file tasks/023-security-diagnostics.md \
  --verify "bash -lc '.venv/Scripts/python.exe scripts/check.py'" \
  --diff-out C:/Users/Artur/projects/reziume-v2/fix.diff --json C:/Users/Artur/projects/reziume-v2/report.json \
  --sandbox danger-full-access --timeout 1800

# 4. дожать скрипты скилла
cd /c/Users/Artur/projects/agent-security-audit
python3 scripts/audit.py --root C:/Users/Artur/projects/reziume-v2 --out C:/Users/Artur/AppData/Local/hermes/cache/scratch/sec/rep5.md
bash scripts/scan-web.sh https://reziume.korobkai.ru
bash scripts/scan-host.sh vps reziume.service
```

## Что было запущено на момент закрытия

| Процесс | Что | Судьба |
|---|---|---|
| `proc_77b6234693c9` | прогон `audit.py` после правки | прервётся, перезапустить |
| `proc_d8259780ea8c` | dsh, тикет 023 (диагностика) | мог не успеть, проверить отчёт |
| `proc_3018abff04dd` | dev-сервер Django на 8123 | не нужен, поднять заново при надобности |
| `proc_55dbc03a752f` | живой пульт dsh на 8099 | поднять: `scripts/live_server.py --port 8099` |

## Открытые вопросы к владельцу

1. Публиковать скилл на GitHub от его аккаунта (`Arturio48`) – нужно подтверждение и
   имя репозитория (`security-audit`?).
2. Пост в Telegram – публиковать самому владельцу или черновик отдать текстом.
3. Порядок закрытий: сначала 024 (быстрые P1), или сразу 025 тоже.
