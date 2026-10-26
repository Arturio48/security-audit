# security-audit

Универсальный скилл для ИИ-агента: провести аудит своего сайта и сервера на
эксплуатируемые слабости, показать доказательства и закрыть найденное.

Работает с любым агентом, который читает `SKILL.md`: Claude Code, Cursor, Codex,
Hermes Agent. Ничего не эксплуатирует и по умолчанию ничего не меняет: три скрипта
только читают и печатают отчёт, правки предлагаются диффом.

## Зачем

Осенью 2026 атака перестала быть ручной. Кампании вроде Cairn/NorForge и ARTEX
ставят веб-шеллы через публичные формы загрузки, а «пентест по подписке» продаёт
скомпрометированную цель за десятки долларов. При этом самая частая причина
компрометации — не экзотическая дыра, а патч-долг, `.env`, уехавший на сервер вместе
с деплоем, и уведомления, собранные без экранирования.

Скилл закрывает именно этот разрыв: он знает, куда смотреть, и не тратит ход агента
на чтение лендингов про безопасность.

## Что внутри

```
SKILL.md                        процедура: 8 шагов, правила, ловушки, критерии приёмки
references/findings-catalog.md  12 классов находок: как обнаружить и как закрыть
references/threats-2026-q4.md   что реально атаковали в сентябре-октябре 2026, со ссылками
references/tooling.md           проверенные инструменты и MCP, что каждый не видит
scripts/audit.py                один запуск: зависимости, секреты, опасные вызовы, деплой
scripts/scan-web.sh             периметр: заголовки, TLS, редиректы, куки, утечки файлов
scripts/scan-host.sh            хост по ssh: sshd, порты, ufw, fail2ban, systemd, права
```

## Установка

**Claude Code** (личный или проектный скилл):

```bash
mkdir -p ~/.claude/skills && git clone https://github.com/<you>/security-audit.git ~/.claude/skills/security-audit
# или в проект:  git clone ... .claude/skills/security-audit
```

**Hermes Agent:**

```bash
mkdir -p ~/.agents/skills && git clone https://github.com/<you>/security-audit.git ~/.agents/skills/security-audit
```

**Cursor:** скопировать `SKILL.md` и `references/` в проект, добавить
`.cursor/rules/security-audit.mdc` с одной строкой: «Follow
`.claude/skills/security-audit/SKILL.md` for any security audit».

**Codex / любой агент с `AGENTS.md`:**

```markdown
## Security audit
Before any security work read `security-audit/SKILL.md` and follow its procedure.
Run `python3 security-audit/scripts/audit.py --root . --out security-report.md` first.
```

## Запуск

```bash
python3 scripts/audit.py --root /path/to/project --out security-report.md
bash scripts/scan-web.sh https://your.site
bash scripts/scan-host.sh your-ssh-host app.service
```

Первый скрипт не требует сети и ничего не устанавливает. Два других требуют `curl`,
`openssl` и (для хоста) неинтерактивного ssh.

## Что он найдёт

- зависимость ниже патченной версии, включая те случаи, где CVE ещё нет и сканеры
  молчат;
- секреты в дереве и в истории, `.env`, который уезжает на сервер вместе с деплоем;
- пользовательский текст, уходящий в мессенджер с `parse_mode=HTML` без экранирования;
- отсутствие HSTS, CSP в режиме «когда-нибудь», куки без `Secure`/`HttpOnly`;
- отсутствие лимитов частоты на заявках, загрузке и входе;
- `sshd` с входом по паролю, сервис под root, порты консолей и MCP наружу;
- файлы загрузок внутри web-root без `noexec`.

Каждой находке в отчёте соответствует команда с выводом, оценка P1/P2/P3, исправление
и откат.

## Чего он не делает

- не эксплуатирует найденное, не подбирает пароли, не фаззит;
- не сканирует чужие адреса;
- не меняет конфигурацию без согласия владельца;
- не заменяет пентест: логические дыры в бизнес-процессе он только подсвечивает.

## Лицензия

MIT. Берите, форкайте, встраивайте в свои пайплайны.
