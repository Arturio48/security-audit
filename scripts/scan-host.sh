#!/usr/bin/env bash
# Аудит хоста по ssh: только чтение конфигурации и статусов.
# Ничего не меняет, не перезапускает, не устанавливает.
#
#   bash scan-host.sh vps            # имя хоста из ~/.ssh/config
#   bash scan-host.sh root@1.2.3.4 app.service
#
# Второй аргумент — имя systemd-юнита приложения (по умолчанию app.service).
set -uo pipefail

SSH_HOST="${1:-}"
UNIT="${2:-app.service}"
if [ -z "$SSH_HOST" ]; then
  echo "использование: bash scan-host.sh <ssh-host> [service-unit]" >&2
  exit 2
fi

SSH="ssh -o BatchMode=yes -o ConnectTimeout=10 $SSH_HOST"
fail=0
ok()   { printf 'ok     %s\n' "$1"; }
bad()  { printf 'FAIL   %s\n' "$1"; fail=1; }
note() { printf 'info   %s\n' "$1"; }

if ! $SSH true 2>/dev/null; then
  echo "нет неинтерактивного доступа по ssh к $SSH_HOST" >&2
  exit 2
fi

echo "== 1. система =="
$SSH 'printf "%s | %s | uptime %s\n" "$(uname -srm)" "$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")" "$(cut -d. -f1 /proc/uptime)s"'
$SSH 'test -f /var/run/reboot-required && echo "требуется перезагрузка" || echo "перезагрузка не требуется"'
$SSH 'command -v unattended-upgrade >/dev/null && systemctl is-enabled unattended-upgrades 2>/dev/null || echo "unattended-upgrades отсутствует"'

echo "== 2. sshd =="
sshd_cfg="$($SSH 'sudo -n sshd -T 2>/dev/null || sshd -T 2>/dev/null' || true)"
if [ -z "$sshd_cfg" ]; then
  bad "sshd -T недоступен (нужен root): проверьте /etc/ssh/sshd_config вручную"
else
  rootlogin="$(printf '%s\n' "$sshd_cfg" | grep -i '^permitrootlogin' | awk '{print $2}')"
  case "$rootlogin" in
    no) ok "PermitRootLogin no" ;;
    prohibit-password|without-password) note "root только по ключу (PermitRootLogin $rootlogin) - допустимо, лучше no" ;;
    *) bad "root может логиниться по ssh (PermitRootLogin ${rootlogin:-по умолчанию})" ;;
  esac
  printf '%s\n' "$sshd_cfg" | grep -qi '^passwordauthentication no' && ok "PasswordAuthentication no" || bad "разрешён вход по паролю"
  printf '%s\n' "$sshd_cfg" | grep -qi '^x11forwarding no' && ok "X11Forwarding no" || note "X11Forwarding включён"
fi

echo "== 3. открытые порты =="
ports="$($SSH 'sudo -n ss -lntp 2>/dev/null || ss -lntp 2>/dev/null')"
printf '%s\n' "$ports" | sed -n '1,25p'
public_risky=""
for p in 5432 6379 9200 27017 2375 5678 3000 3001 8090 8000 11434; do
  if printf '%s\n' "$ports" | grep -qE "(0\.0\.0\.0|\*|\[::\]):$p\b"; then
    public_risky="$public_risky $p"
  fi
done
if [ -n "$public_risky" ]; then
  bad "наружу опубликованы порты:$public_risky (docker публикует мимо ufw: смотреть docker ps)"
  $SSH 'docker ps --format "{{.Names}} {{.Ports}}" 2>/dev/null' | sed 's/^/       /'
else
  ok "публичных портов из списка риска нет"
fi

echo "== 4. фаервол и fail2ban =="
$SSH 'sudo -n ufw status verbose 2>/dev/null || echo "ufw недоступен"' | sed -n '1,6p'
jails="$($SSH 'sudo -n fail2ban-client status 2>/dev/null' || true)"
if [ -z "$jails" ]; then
  note "fail2ban не найден или нужен root"
else
  printf '%s\n' "$jails"
fi

echo "== 5. сервис $UNIT =="
unit="$($SSH "systemctl show $UNIT -p User -p NoNewPrivileges -p ProtectSystem -p PrivateTmp -p FragmentPath 2>/dev/null")"
printf '%s\n' "$unit" | sed -n '1,8p'
printf '%s\n' "$unit" | grep -qi 'User=root' && bad "$UNIT работает от root"
printf '%s\n' "$unit" | grep -qi 'NoNewPrivileges=yes' && ok "NoNewPrivileges=yes" || note "NoNewPrivileges не включён"
printf '%s\n' "$unit" | grep -qi 'ProtectSystem=\(strict\|full\)' && ok "ProtectSystem включён" || note "ProtectSystem не включён"
printf '%s\n' "$unit" | grep -qi 'PrivateTmp=yes' && ok "PrivateTmp=yes" || note "PrivateTmp не включён"
envfile="$($SSH "systemctl show $UNIT -p EnvironmentFiles 2>/dev/null" | sed 's/^EnvironmentFiles=//; s/ (ignore_errors=.*)$//')"
for f in $envfile; do
  perm="$($SSH "sudo -n stat -c '%a %U:%G' $f 2>/dev/null" || true)"
  [ -n "$perm" ] || continue
  mode="${perm%% *}"
  case "$mode" in
    600|400) ok "права $f: $perm" ;;
    *) note "права $f: $perm (лучше 600; если группа сервиса - 640 допустимо)" ;;
  esac
done

echo "== 6. файлы приложения =="
$SSH 'for d in /opt/reziume /srv/app /var/www; do [ -d "$d" ] && ls -ld "$d" && ls -la "$d" | head -12; done 2>/dev/null'
$SSH 'for e in /opt/*/.env /srv/*/.env /var/www/*/.env; do [ -f "$e" ] && ls -l "$e"; done 2>/dev/null' |
  sed 's/^/       /' || true
if $SSH 'ls /opt/*/.env >/dev/null 2>&1'; then
  bad "в каталоге приложения лежит .env — секреты дублируются вне EnvironmentFile"
fi

echo "== 7. каталог загрузок =="
$SSH 'findmnt -no TARGET,OPTIONS /var/lib 2>/dev/null; for m in /opt/*/media /srv/*/media; do [ -d "$m" ] && findmnt -no TARGET,OPTIONS --target "$m" 2>/dev/null; done' | sed -n '1,6p'

echo "== 8. недавние входы =="
$SSH 'last -n 8 -i 2>/dev/null | head -8'

echo
[ "$fail" -eq 0 ] && echo "хост: проверки пройдены" || echo "хост: есть находки, см. FAIL выше"
exit "$fail"
