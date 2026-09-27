#!/usr/bin/env bash
# Установка goosko-online на сервер (Ubuntu/Debian).
# Запускать с правами sudo с каталога репозитория:  sudo ./deploy/install.sh
#
# Что делает:
#   * создаёт пользователя/группу goosko, каталоги /opt/goosko-online и /var/www/storage
#   * ставит python-venv и зависимости
#   * создаёт /etc/goosko/goosko.env (если нет) с новым SECRET_KEY
#   * устанавливает systemd unit goosko-web
# НЕ трогает nginx и ssh-скрипты — см. DEPLOY.md.

set -euo pipefail

APP_DIR=/opt/goosko-online
STORAGE_DIR=/var/www/storage
ENV_FILE=/etc/goosko/goosko.env
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "== 1. Пользователь и каталоги =="
getent group www-data >/dev/null || groupadd www-data
id -u goosko >/dev/null 2>&1 || useradd -r -m -g www-data -s /usr/sbin/nologin goosko

mkdir -p "$APP_DIR" "$STORAGE_DIR"/{public,private,trash,media} /etc/goosko

echo "== 2. Код приложения =="
rsync -a --delete \
    --exclude '.git' --exclude '__pycache__' --exclude 'tests/__pycache__' \
    --exclude 'users.db' --exclude '.pytest_cache' \
    "$SRC_DIR/" "$APP_DIR/"

echo "== 3. Python-окружение =="
apt-get install -y python3-venv python3-pip rsync sqlite3 >/dev/null
test -d /opt/goosko-venv || python3 -m venv /opt/goosko-venv
/opt/goosko-venv/bin/pip install -q --upgrade pip
/opt/goosko-venv/bin/pip install -q -r "$APP_DIR/requirements.txt"

echo "== 4. Конфигурация =="
if [[ ! -f "$ENV_FILE" ]]; then
    install -m 600 /dev/null "$ENV_FILE"
    cp "$SRC_DIR/deploy/goosko.env.example" "$ENV_FILE"
    SECRET=$(openssl rand -hex 32)
    sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$SECRET/" "$ENV_FILE"
    sed -i '/^#ADMIN_PASSWORD=/d' "$ENV_FILE"
    echo "Создан $ENV_FILE. ВНИМАТЕЛЬНО проверьте пути и адреса!"
    echo "Пароль первого администратора будет напечатан в журнале при первом запуске:"
    echo "  journalctl -u goosko-web | head"
else
    echo "$ENV_FILE уже существует — не трогаем."
fi

echo "== 5. Права =="
chown -R goosko:www-data "$APP_DIR" "$STORAGE_DIR"
chmod 750 "$STORAGE_DIR"
chmod 640 "$APP_DIR/users.db" 2>/dev/null || true

echo "== 6. systemd =="
install -m 644 "$SRC_DIR/deploy/goosko-web.service" /etc/systemd/system/goosko-web.service
systemctl daemon-reload
systemctl enable goosko-web

cat <<'EOF'

Установка завершена. Дальнейшие шаги (см. DEPLOY.md):
  1) разместить /usr/local/bin/goosko-power.sh + goosko-ssh-sign.sh/revoke.sh
     и выполнить: deploy/install-sudoers.sh
  2) настроить nginx (X-Accel-Redirect + auth_request /check)
  3) systemctl start goosko-web && journalctl -u goosko-web | head
     -> скопировать одноразовый пароль admin, войти и сменить его
EOF
