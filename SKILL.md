---
name: security-audit
description: "Find exploits in a web service and close them safely."
version: 1.0.0
author: Artur Korobkin (Arturio48), Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, audit, django, vps, hardening, exploits, ai-agents]
    related_skills: [requesting-code-review, infra-security-remediation]
---

# Security Audit Skill

Read-only, evidence-first audit of a web service and the host it runs on: dependency
floors, secret leaks, injection sinks, perimeter and TLS, sshd and systemd hardening,
plus the agent surface (MCP servers, keys, exposed consoles). Every finding carries
the command that produced it and a concrete fix.

It does not exploit anything, does not brute force, and does not scan hosts you do not
own. Default mode changes nothing; fixes are proposed as diffs and applied only after
the owner agrees.

## When to Use

- "Проверь сайт на дыры", "что у нас может сломать атакующий", "подготовься к аудиту".
- Before publishing a service, after adding file uploads, auth, payments or an agent.
- Recurring check: weekly dependency + CVE pass, monthly host pass.
- Don't use for: pentesting someone else's asset, load testing, malware analysis,
  or code review for correctness (`requesting-code-review`).

## Prerequisites

- `python3` (stdlib only for `scripts/audit.py`).
- Optional, in this order of value: `pip-audit`, `bandit`, `gitleaks`, `trivy`,
  `semgrep`, `osv-scanner`, `ssh-audit`, `testssl.sh`. Missing tools degrade the
  report, they do not stop it.
- Read access to the repository and, for the host pass, non-interactive ssh
  (`ssh -o BatchMode=yes <host> true` must succeed).
- Never needs a model key, never sends secrets anywhere.

## How to Run

```
python3 scripts/audit.py --root . --out security-report.md        # code + deps + secrets
bash scripts/scan-web.sh https://example.com                      # perimeter, TLS, headers
bash scripts/scan-host.sh <ssh-host>                              # host, read-only
```

Each script prints findings and exits non-zero only on a failed check, never on
"nothing found". See `references/tooling.md` for install lines per OS.

## Quick Reference

| Goal | Command |
|---|---|
| deps with live advisories | `pip-audit -r requirements.txt` |
| deps in a uv project | `uv export --frozen --no-dev --no-hashes > r.txt && pip-audit -r r.txt` |
| python sinks | `bandit -r app -q` |
| secrets in history | `gitleaks detect --source . --redact` |
| django deploy flags | `manage.py check --deploy` (with the PRODUCTION env file) |
| headers + TLS | `curl -sI https://host/` , `testssl.sh --quiet host` |
| sshd policy | `sshd -T` on the host |
| exposed ports | `ss -lntp` on the host |

## Procedure

1. **Scope and inventory.** Read the deploy script, settings, entry points, and the
   list of public routes. Write down: stack, versions, public surfaces (uploads, auth,
   payments, admin, webhooks, agents), and where secrets live.
   *Done when* the report has a stack table with versions taken from lockfiles, not
   from memory.
2. **Dependencies.** Run the dep scan against the **lockfile export**, never against
   the installed venv of another project. Record every advisory with its boundary
   version. Then check the *pre-CVE blind spot*: read the project's changelogs for
   security releases newer than the pinned version (`references/findings-catalog.md`,
   class 1). *Done when* each dependency is marked current / behind / vulnerable.
3. **Secrets.** Scan the tree and git history. Then read the deploy mechanism: what
   actually ships to the server. A `.env` that is gitignored but not excluded from the
   transfer archive is a finding. *Done when* every secret's storage (env file, systemd
   unit, vault) and every place it is copied to are listed.
4. **Code sinks.** Grep the classes in `references/findings-catalog.md`: HTML/format
   injection into templates or messengers, user-supplied `Content-Type`, file upload
   handling, IDOR on tokens, SSRF in outbound fetches, `eval`/`pickle`/`yaml.load`,
   rate limits on write endpoints. Prefer `bandit` output plus targeted greps.
   *Done when* each public route has a verdict and a file:line for every hit.
5. **Perimeter.** Headers, TLS version and certificate, redirects, cookie flags, HSTS,
   admin path exposure, backup/`.git`/`/static` listing, and error pages that leak a
   stack trace. *Done when* the report shows the raw response headers and the TLS
   summary.
6. **Host.** sshd policy, sudo rules, systemd hardening flags, listening sockets,
   firewall, fail2ban jails, file permissions on env and media, unattended upgrades,
   and what runs as root that should not. *Done when* every listening socket is either
   public-on-purpose or a finding.
7. **Agent surface** (skip if the service has no agent). Console ports on non-loopback,
   MCP configs containing literal keys, agent tokens without TTL, a coding agent with
   write access to the production checkout. See `references/threats-2026-q4.md`, section
   "Agent surface".
8. **Report.** Use the template at the end of `references/findings-catalog.md`: finding,
   severity (P1 critical / P2 important / P3 hardening), evidence (command + output
   excerpt), fix (exact diff or command), rollback. Order by exploitability, not by
   file order. *Done when* a person who was not in the audit can reproduce each finding
   from the report alone.

## Rules

- **Read-only by default.** No config edits, no restarts, no `rm`, no `--force`.
- **No exploitation and no brute force.** Check the *presence* of a weakness; do not
  prove it by breaking in. No credential stuffing, no fuzzing of someone else's host.
- **Only the owner's assets.** Confirm ownership before the perimeter pass; stop if the
  target is not the user's.
- **Secrets never leave the machine.** Print lengths and hashes, not values; redact in
  reports; never paste a token into a chat, an issue or a commit.
- **Fixes are diffs.** Propose the smallest change, name the rollback, and let the
  owner approve. A security fix that breaks deploy is a new outage.
- **Distinguish fact from inference.** A vendor blog is not a CVE. A pre-CVE advisory is
  labelled as such, with its range and its source.

## Pitfalls

1. **Scanner green does not mean safe.** Advisories published as pre-CVE (vendor-only)
   are invisible to `pip-audit`/OSV. Real case: gunicorn 23.0.0 sits inside a
   request-smuggling range fixed in 26.1.0 while every scanner reports "no known
   vulnerabilities". Always compare versions against vendor changelogs.
2. **`manage.py check --deploy` lies locally.** With a dev `.env` (`DEBUG=True`) it
   reports missing HSTS and secure cookies that production already sets. Run it with
   the production environment file, or the report will contain six false findings.
3. **Static assets lag after a restart.** A post-deploy check that greps the served CSS
   seconds after `systemctl restart` can read the previous file. Retry for ~15 seconds
   before declaring a failed deploy.
4. **Hashed asset names.** With `ManifestStaticFilesStorage` the HTML points at
   `app.<hash>.css`; a check hardcoded to `app.css` may match an older copy. Parse the
   URL from the HTML.
5. **Gitignored is not unshipped.** `.env` in `.gitignore` is still tarred by a deploy
   script that ships the working tree. Read the transfer command, not the ignore file.
6. **HTML injection into notification channels** fails silently: malformed markup makes
   the messenger API return 400 and the notification is simply lost. Check escaping
   before blaming the network.
7. **Trusting one source.** Cross-check every CVE id against the vendor advisory or the
   CVE record. Aggregator posts invent ranges and dates.

## Verification

- The report contains N findings, each with a command and an output excerpt.
- Re-running the same scripts produces the same findings (no flaky checks).
- For every closed finding, a re-scan shows it gone and the deploy still passes its
  own gate.
- No secret value appears anywhere in the report or the chat log.

## Files

- `references/findings-catalog.md` — the finding classes with detect/fix recipes and the
  report template.
- `references/threats-2026-q4.md` — what attackers actually did in Q4 2026, with sources.
- `references/tooling.md` — verified tools, install lines, what each misses, MCP options.
- `scripts/audit.py` — one-command static pass (deps, secrets, sinks) → Markdown.
- `scripts/scan-web.sh`, `scripts/scan-host.sh` — perimeter and host passes.
