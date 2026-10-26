# Инструменты: что проверено и что из этого брать

Все строки проверены по реестрам и официальным докам в октябре 2026. Версия указана
как ориентир, перед установкой взять актуальную.

## Обязательный минимум

| Инструмент | Что даёт | Установка | Чего не видит |
|---|---|---|---|
| `pip-audit` | CVE в Python-зависимостях по lock | `uv tool install pip-audit` | pre-CVE вендорские advisories; не-Python стек |
| `bandit` | опасные вызовы в Python | `uv tool install bandit` | логику, права, конфигурацию |
| `gitleaks` | секреты в рабочем дереве и в истории git | `winget install Gitleaks.Gitleaks` / бинарь с GitHub / `apt install gitleaks` | секреты в env сервера |
| `trivy fs` | зависимости, IaC, секреты, SBOM | `winget install AquaSecurity.Trivy` / бинарь | логику приложения; телеметрия включена по умолчанию, ставить `--disable-telemetry` |
| `ssh-audit` | политика sshd и версии алгоритмов | `uv tool install ssh-audit` | конфигурацию sudo и firewall |
| `testssl.sh` | TLS: версии, шифры, цепочка, известные дыры | бинарь с GitHub | приложение |

Пример цепочки для проекта на Python:

```
uv export --frozen --no-dev --no-hashes > r.txt
pip-audit -r r.txt
bandit -r app -q
gitleaks detect --source . --redact --no-banner
trivy fs --scanners vuln,secret,misconfig --disable-telemetry .
```

## По типам задач

- **Зависимости и лицензии:** `pip-audit`, `osv-scanner`, `trivy fs`, `npm audit` /
  `pnpm audit`. Лицензии: `pip-licenses`, `license-checker`.
- **Код приложения:** `bandit` (Python), `semgrep` (мультиязычный, правила `p/security-audit`).
- **Секреты:** `gitleaks`, `trufflehog` (ищет и в удалённых репозиториях, есть верификация ключей).
- **Контейнеры и IaC:** `trivy image`, `grype`, `syft` (SBOM), `hadolint`, `checkov`.
- **Живой веб:** `nuclei` (шаблоны известных CVE; только для своих целей), `zap` (baseline-скан), `nikto`.
- **Хост и TLS:** `lynis`, `ssh-audit`, `testssl.sh`, `nmap -sV` для своих адресов.

## MCP-серверы (для агента)

| Сервер | Транспорт | Состояние | Комментарий |
|---|---|---|---|
| Snyk MCP | stdio/http | активен | код, зависимости, контейнеры, IaC, SBOM; нужен ключ Snyk |
| `semgrep mcp` | stdio / streamable-http | активен | MCP встроен в CLI; отдельный репозиторий `semgrep/mcp` архивирован в 2025 |
| `trivy plugin install mcp` | stdio | существует | не обновлялся с декабря 2025, использовать как есть, без ожиданий |
| GitHub MCP | stdio/http | активен | для code scanning alerts и Dependabot-алертов репозитория |

Чего не существует (проверено в реестрах, не ставьте): `@semgrep/mcp` в npm,
`trivy-mcp` и `mcp-server-git` — заглушки `0.0.1-security`.

Правила подключения MCP к агенту: только loopback, ключи в env, а не в JSON-конфиге;
сервер, который читает и пишет в прод, отделять от читающего; логи MCP не должны
содержать токены.

## Гигиена инструментов

- Ставить из официального реестра или релиза, проверять подпись/контрольную сумму.
- Не давать агенту деструктивные флаги: `--fix`, `--auto-approve`, `rm`, `--force`,
  переустановку зависимостей в прод-venv.
- Сканеры дают ложные срабатывания: каждую находку подтверждать чтением кода, а не
  переносить в отчёт «как есть».
- Телеметрия: `trivy --disable-telemetry`, у `semgrep` проверить `--metrics=off` для
  приватных репозиториев.
