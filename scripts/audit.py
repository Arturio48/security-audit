#!/usr/bin/env python3
"""Read-only security pass over a repository: dependencies, secrets, sinks.

Usage:
    python3 audit.py --root . --out security-report.md

Never writes outside --out, never sends anything over the network, never prints a
secret value (only a redacted shape). Missing optional tools degrade the report.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
             ".pytest_cache", "staticfiles", "dist", "build", ".tox"}

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic bearer", re.compile(r"(?i)\b(?:api[_-]?key|secret|token)\b\s*[:=]\s*['\"]([A-Za-z0-9_\-]{24,})['\"]")),
]

SINK_PATTERNS = [
    ("eval/exec", re.compile(r"\b(?:eval|exec)\s*\("), "P2", "Выполнение строки как кода: только для доверенного ввода."),
    ("pickle.load", re.compile(r"pickle\.loads?\s*\("), "P2", "Десериализация pickle = исполнение кода."),
    ("yaml.load без SafeLoader", re.compile(r"yaml\.load\s*\((?![^)]*SafeLoader)"), "P2", "Использовать safe_load."),
    ("subprocess shell=True", re.compile(r"shell\s*=\s*True"), "P2", "Разбор аргументов через shell."),
    ("urllib urlopen", re.compile(r"\burlopen\s*\("), "P3", "Проверить схему и хост, иначе SSRF."),
    ("HTML в мессенджер", re.compile(r"parse_mode\s*[=:]\s*[\"']HTML[\"']"), "P3",
     "Проверить, экранируются ли подстановки: html.escape для каждой."),
    # только сборка запроса из переменных: литерал вроде execute("SELECT 1") безопасен
    ("SQL строкой", re.compile(r"\.(?:raw|execute)\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*%|\w+\s*\+|\w+\s*%)"), "P1",
     "Возможна инъекция: передавать параметры, а не склеивать строку."),
]

SKIP_SINK_DIRS = {"tests", "test", "testing", "migrations", "docs", "examples", "vendor"}


DEPLOY_EXCLUDE_HINTS = ("tar ", "rsync ", "--exclude")


def sh(cmd: list[str], cwd: Path, timeout: int = 300) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return 127, str(exc)


def walk_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip",
                                   ".gz", ".ico", ".woff", ".woff2", ".ttf", ".mp4", ".so", ".pyc"}:
            continue
        try:
            if path.stat().st_size > 2_000_000:
                continue
        except OSError:
            continue
        yield path


def redact(value: str) -> str:
    head = value[:4]
    return f"{head}…({len(value)} симв.)"


def scan_secrets(root: Path) -> list[dict]:
    findings = []
    env_files = []
    for path in walk_files(root):
        name = path.name
        if name == ".env" or name.startswith(".env."):
            env_files.append(str(path.relative_to(root)))
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name_rx, rx in SECRET_PATTERNS:
            for match in rx.finditer(text):
                line = text[: match.start()].count("\n") + 1
                raw = match.group(1) if match.groups() else match.group(0)
                findings.append({
                    "title": f"Похоже на секрет: {name_rx}",
                    "severity": "P1",
                    "where": f"{path.relative_to(root)}:{line}",
                    "evidence": f"найден фрагмент {redact(raw)}",
                    "fix": "Перенести в EnvironmentFile с правами 600, отозвать и перевыпустить ключ.",
                })
    if env_files:
        findings.append({
            "title": "Env-файлы на диске",
            "severity": "info",
            "where": ", ".join(env_files[:5]),
            "evidence": "значения не печатаются; сам файл — норма, вопрос в его судьбе",
            "fix": "Проверить: файл в .gitignore, права 600, и он не уезжает деплоем (см. ниже).",
        })
    return findings


def scan_sinks(root: Path) -> list[dict]:
    findings = []
    seen = set()
    for path in walk_files(root):
        if path.suffix.lower() not in {".py", ".js", ".ts", ".php", ".rb", ".go"}:
            continue
        if any(part.lower() in SKIP_SINK_DIRS for part in path.parts):
            continue
        if path.name.startswith(("test_", "spec_")):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name_rx, rx, sev, why in SINK_PATTERNS:
            key = (name_rx, str(path))
            if key in seen:
                continue
            match = rx.search(text)
            if not match:
                continue
            seen.add(key)
            line = text[: match.start()].count("\n") + 1
            findings.append({
                "title": f"Опасный вызов: {name_rx}",
                "severity": sev,
                "where": f"{path.relative_to(root)}:{line}",
                "evidence": text.splitlines()[line - 1].strip()[:120],
                "fix": why,
            })
    return findings


def scan_deploy_excludes(root: Path) -> list[dict]:
    findings = []
    rx = re.compile(r"--exclude[=\s]+['\"]?([^\s'\";]+)")
    for path in root.rglob("*.sh"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "--exclude" not in text:
            continue
        patterns = [p.strip("'\"") for p in rx.findall(text)]
        if any(p == ".env" or p.startswith(".env") for p in patterns):
            continue
        findings.append({
            "title": "Деплой-скрипт не исключает .env",
            "severity": "P1",
            "where": str(path.relative_to(root)),
            "evidence": "в командах передачи есть --exclude, но .env в списке нет",
            "fix": "Добавить --exclude=.env --exclude='.env.*'; проверить, что файла нет на сервере.",
        })
    return findings


def scan_rate_limits(root: Path) -> list[dict]:
    has_post = False
    has_limit = False
    for path in walk_files(root):
        if path.suffix.lower() != ".py":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if re.search(r"(?i)method\s*=\s*[\"']POST[\"']|def post\(", text):
            has_post = True
        if re.search(r"(?i)ratelimit|throttle|rate_limit", text):
            has_limit = True
    if has_post and not has_limit:
        return [{
            "title": "Нет ограничения частоты на записывающих ручках",
            "severity": "P2",
            "where": "весь проект",
            "evidence": "найдены POST-обработчики, упоминаний ratelimit/throttle нет",
            "fix": "Счётчик на IP+ключ с окном 1-10 минут; лимит размера тела; лимит на /login и /upload.",
        }]
    return []


def pip_audit_cmd() -> list[str] | None:
    if shutil.which("pip-audit"):
        return ["pip-audit"]
    if shutil.which("uv"):
        return ["uv", "tool", "run", "pip-audit"]
    if shutil.which("python3") or shutil.which("python"):
        return [sys.executable, "-m", "pip_audit"]
    return None


def scan_deps(root: Path) -> list[dict]:
    findings = []
    audit = pip_audit_cmd()
    if audit is None:
        findings.append({
            "title": "pip-audit не установлен: зависимости не проверены",
            "severity": "P3",
            "where": "окружение",
            "evidence": "ни pip-audit, ни uv, ни модуль pip_audit не найдены",
            "fix": "uv tool install pip-audit (или pipx install pip-audit) и повторить.",
        })
        return findings

    req = None
    if (root / "uv.lock").exists() and shutil.which("uv"):
        code, _ = sh(["uv", "export", "--frozen", "--no-dev", "--no-hashes", "--output-file", ".audit-req.txt"], root)
        candidate = root / ".audit-req.txt"
        if code == 0 and candidate.exists():
            req = candidate
    if req is None:
        for name in ("requirements.txt", "requirements-prod.txt"):
            if (root / name).exists():
                req = root / name
                break
    if req is None:
        findings.append({
            "title": "Не найден список зависимостей",
            "severity": "P3",
            "where": str(root),
            "evidence": "нет ни uv.lock, ни requirements.txt",
            "fix": "Экспортировать lock в requirements.txt и прогнать pip-audit.",
        })
        return findings

    code, out = sh(audit + ["-r", str(req), "--progress-spinner", "off"], root)
    if code not in (0, 1):
        findings.append({
            "title": "pip-audit завершился ошибкой",
            "severity": "P3", "where": str(req),
            "evidence": out.strip()[-400:], "fix": "Разобрать вывод вручную.",
        })
        return findings
    if "No known vulnerabilities found" in out:
        findings.append({
            "title": "pip-audit: известных уязвимостей нет",
            "severity": "info", "where": str(req.relative_to(root)),
            "evidence": "проверка пройдена",
            "fix": "Помнить про pre-CVE: сравнить версии периметра с changelog вендоров вручную.",
        })
    else:
        for line in out.splitlines():
            if re.search(r"(?i)CVE-|GHSA-|fix", line):
                findings.append({
                    "title": "Уязвимая зависимость", "severity": "P1",
                    "where": str(req.relative_to(root)), "evidence": line.strip()[:200],
                    "fix": "Поднять версию до последней патченной, пол в lock, перезапуск.",
                })
    try:
        if req.name == ".audit-req.txt":
            req.unlink()
    except OSError:
        pass
    return findings


def render(root: Path, findings: list[dict]) -> str:
    order = {"P1": 0, "P2": 1, "P3": 2, "info": 3}
    findings = sorted(findings, key=lambda f: order.get(f["severity"], 4))
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    lines = [
        f"# Аудит безопасности `{root.name}`",
        "",
        f"Находок: {len(findings)} "
        f"(P1: {counts.get('P1', 0)}, P2: {counts.get('P2', 0)}, P3: {counts.get('P3', 0)}, "
        f"info: {counts.get('info', 0)})",
        "",
        "Сгенерировано `scripts/audit.py`: только чтение файлов, без сети и без изменений.",
        "",
        "## Находки",
        "",
    ]
    if not findings:
        lines += ["Ничего не найдено. Это не значит «безопасно»: см. `references/findings-catalog.md`,", "раздел про pre-CVE и конфигурацию хоста.", ""]
    for i, f in enumerate(findings, 1):
        lines += [
            f"### F{i} · {f['severity']} · {f['title']}",
            f"- Где: `{f['where']}`",
            f"- Доказательство: {f['evidence']}",
            f"- Исправление: {f['fix']}",
            "",
        ]
    lines += [
        "## Дальше",
        "",
        "1. Периметр: `bash scripts/scan-web.sh https://<host>`.",
        "2. Хост: `bash scripts/scan-host.sh <ssh-host>`.",
        "3. Сверить версии периметра с changelog вендоров (pre-CVE слепая зона).",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Read-only security pass")
    ap.add_argument("--root", default=".", help="каталог проекта")
    ap.add_argument("--out", default="security-report.md", help="куда писать отчёт")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"нет каталога: {root}", file=sys.stderr)
        return 2

    findings: list[dict] = []
    findings += scan_deps(root)
    findings += scan_secrets(root)
    findings += scan_deploy_excludes(root)
    findings += scan_sinks(root)
    findings += scan_rate_limits(root)

    report = render(root, findings)
    Path(args.out).write_text(report, encoding="utf-8")

    p1 = sum(1 for f in findings if f["severity"] == "P1")
    print(f"находок: {len(findings)} (P1: {p1}); отчёт: {args.out}")
    if (root / "manage.py").exists():
        print("Django: запустите `manage.py check --deploy` с ПРОД-окружением, не с dev .env.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
