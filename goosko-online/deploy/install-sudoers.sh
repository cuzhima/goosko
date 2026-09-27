#!/usr/bin/env bash
# Установка привилегий sudo для сервисных скриптов goosko.
# Запускать от root:  sudo ./deploy/install-sudoers.sh
#
# Даём пользователю goosko право запускать БЕЗ пароля ТОЛЬКО три конкретных
# скрипта с абсолютными путями. Скрипты должны принадлежать root и не быть
# записываемыми для группы/других (проверяется ниже).

set -euo pipefail

SUDOERS_SNIPPET=/etc/sudoers.d/goosko-online

for script in /usr/local/bin/goosko-power.sh \
              /usr/local/bin/goosko-ssh-sign.sh \
              /usr/local/bin/goosko-ssh-revoke.sh; do
    if [[ ! -f "$script" ]]; then
        echo "ВНИМАНИЕ: $script не найден — пропустить нельзя," >&2
        echo "сначала разместите скрипт, затем повторите установку." >&2
        exit 1
    fi
    # Ужесточаем права: root-writable only
    chown root:root "$script"
    chmod 0755 "$script"
done

cat > "$SUDOERS_SNIPPET" <<'EOF'
# Автоматически создан deploy/install-sudoers.sh — не редактируйте на глаз.
goosko ALL=(root) NOPASSWD: /usr/local/bin/goosko-power.sh poweroff, \
                             /usr/local/bin/goosko-power.sh reboot, \
                             /usr/local/bin/goosko-ssh-sign.sh, \
                             /usr/local/bin/goosko-ssh-revoke.sh
EOF

chmod 0440 "$SUDOERS_SNIPPET"
visudo -cf "$SUDOERS_SNIPPET"
echo "OK: правила sudo установлены ($SUDOERS_SNIPPET)"
