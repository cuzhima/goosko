#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Запустите: sudo $0" >&2
    exit 1
fi

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="/usr/local/sbin"
CONF_DIR="/etc/goosko"
DISK="${DISK:-/dev/sda}"
TARGET_USER="${SUDO_USER:-andrey}"

if ! id "$TARGET_USER" >/dev/null 2>&1; then
    echo "Пользователь $TARGET_USER не существует" >&2
    exit 1
fi

echo "== Установка Goosko System =="
echo "Исходники: $SRC"
echo "Пользователь: $TARGET_USER, диск: $DISK"

install -d -m 0755 "$BIN" "$CONF_DIR" /run/goosko /etc/sysctl.d /etc/sudoers.d

for helper in goosko-display goosko-power goosko-disk-tune goosko-thermal goosko-funnel; do
    install -m 0755 "$SRC/$helper" "$BIN/$helper"
    echo "  helper: $BIN/$helper"
done

if [ ! -f "$CONF_DIR/thermal.conf" ]; then
    sed "s|^DISK=.*|DISK=$DISK|" "$SRC/thermal.conf" > "$CONF_DIR/thermal.conf"
    chmod 0644 "$CONF_DIR/thermal.conf"
    echo "  config: $CONF_DIR/thermal.conf"
else
    echo "  config: $CONF_DIR/thermal.conf уже есть, не трогаю"
fi

if [ ! -f "$CONF_DIR/power_profile" ]; then
    echo "eco" > "$CONF_DIR/power_profile"
    chmod 0644 "$CONF_DIR/power_profile"
fi

install -m 0644 "$SRC/99-goosko-power.conf" /etc/sysctl.d/99-goosko-power.conf
sysctl --system >/dev/null
echo "  sysctl: применено"

install -m 0644 "$SRC/00-goosko-map.conf" /etc/angie/http.d/00-goosko-map.conf
echo "  angie: map установлен"

python3 "$SRC/patch-angie.py"
python3 "$SRC/patch-fstab.py"

if ! findmnt -no OPTIONS / 2>/dev/null | grep -q 'noatime'; then
    mount -o remount,noatime / 2>/dev/null || true
fi

install -m 0644 "$SRC/goosko-power.service" /etc/systemd/system/goosko-power.service
sed "s|/dev/sda|$DISK|g" "$SRC/goosko-disk-tune.service" \
    > /etc/systemd/system/goosko-disk-tune.service
install -m 0644 "$SRC/goosko-thermal.service" /etc/systemd/system/goosko-thermal.service
chmod 0644 /etc/systemd/system/goosko-disk-tune.service

sed "s/^andrey /$TARGET_USER /" "$SRC/goosko-sudoers" > /etc/sudoers.d/goosko
chmod 0440 /etc/sudoers.d/goosko
if command -v visudo >/dev/null 2>&1; then
    if ! visudo -cf /etc/sudoers.d/goosko >/dev/null; then
        rm -f /etc/sudoers.d/goosko
        echo "Ошибка sudoers: файл удалён" >&2
        exit 1
    fi
fi
echo "  sudoers: разрешены 6 помощников для $TARGET_USER"

systemctl daemon-reload
for unit in goosko-power.service goosko-disk-tune.service goosko-thermal.service; do
    if ! systemctl enable --now "$unit"; then
        echo "Внимание: $unit не запустился, смотрите journalctl -u $unit" >&2
    fi
done

if systemctl is-active --quiet angie.service; then
    systemctl reload angie.service || echo "Внимание: не удалось перезагрузить Angie" >&2
fi
if systemctl is-enabled --quiet goosko-web.service 2>/dev/null; then
    systemctl restart goosko-web.service || echo "Внимание: не удалось перезапустить goosko-web" >&2
fi

echo
echo "== Готово =="
systemctl --no-pager --lines=0 status goosko-thermal.service || true
echo
echo "Проверить:"
echo "  sudo -u $TARGET_USER sudo -n $BIN/goosko-display status"
echo "  curl -s http://127.0.0.1:5000/system/status"
if command -v smartctl >/dev/null 2>&1; then
    echo
    smartctl -H "$DISK" 2>/dev/null | grep -E 'SMART overall|result' || true
fi
