# Деплой goosko-online

## Быстрый старт (чистый сервер Ubuntu/Debian)

```bash
git clone <репозиторий> && cd goosko-online
sudo ./deploy/install.sh
```

Скрипт создаёт пользователя `goosko`, каталоги, venv, конфиг
`/etc/goosko/goosko.env` (с генерацией `SECRET_KEY`) и systemd unit.

## После установки — по шагам

### 1. Сервисные скрипты root (камера/питание/SSH)

Приложение запускается от непривилегированного пользователя `goosko` и
вызывает три root-скрипта через `sudo -n`. Разместите их:

**/usr/local/bin/goosko-power.sh**
```bash
#!/bin/sh
case "$1" in
    poweroff) exec /sbin/shutdown -h now ;;
    reboot)   exec /sbin/shutdown -r now ;;
    *) echo "usage: $0 {poweroff|reboot}" >&2; exit 2 ;;
esac
```

`goosko-ssh-sign.sh` / `goosko-ssh-revoke.sh` — ваши существующие скрипты
подписи SSH-сертификатов (см. `/opt/goosko-online`, если уже лежат).

Затем:
```bash
sudo ./deploy/install-sudoers.sh
```
Правила sudo выданы **только** на конкретные команды
(`goosko-power.sh poweroff|reboot`), не на весь скрипт целиком.

### 2. Конфигурация

Отредактируйте `/etc/goosko/goosko.env` (права 600):
адреса `PUBLIC_BASE_URL` / `FUNNEL_HOST`, устройства камеры, лимиты.
Полный список переменных — в `deploy/goosko.env.example`.

### 3. Nginx (отдача файлов + auth_request)

Flask проверяет права и отдаёт `X-Accel-Redirect`; файл добирает nginx.
Для служебной проверки сессии есть `GET /check` (200/401).

```nginx
location /protected/ {
    internal;
    alias /var/www/storage/private/;
}
location /public-protected/ {
    internal;
    alias /var/www/storage/public/;
}
location /storage-public/ {
    internal;
    auth_request /check;
    alias /var/www/storage/public/;
}
location = /check {
    internal;
    proxy_pass http://127.0.0.1:5000/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}
location / {
    proxy_pass http://127.0.0.1:5000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 4g;
}
```

Если nginx не настроен — поставьте в env `USE_X_ACCEL=0`, файлы будет
отдавать сам Flask (медленнее, но безопасно).

### 4. Первый запуск

```bash
sudo systemctl start goosko-web
journalctl -u goosko-web | head
```

При первой инициализации БД в журнал печатается **одноразовый пароль**
пользователя `admin` — войдите и немедленно смените его (страница
«Аккаунт»). Либо задайте `ADMIN_PASSWORD` в env **до** первого запуска.

### 5. Резервные копии

```cron
15 3 * * * /opt/goosko-online/deploy/backup.sh >> /var/log/goosko-backup.log 2>&1
```

Бэкапы в `/var/backups/goosko/<дата>/`: консистентная копия `users.db`
(через `sqlite3 .backup`) и tar.gz хранилища; ротация 14 дней.

### 6. Обновление версии

```bash
cd <клон репозитория> && git pull
python3 -m venv /tmp/gt && /tmp/gt/bin/pip install -r requirements-dev.txt
cd goosko-online && /tmp/gt/bin/python -m pytest     # все тесты должны пройти
sudo ./deploy/install.sh                              # rsync не трогает users.db
sudo systemctl restart goosko-web
```

## Проверка безопасности после деплоя

- `curl -sI https://…/` → заголовки CSP, HSTS, X-Frame-Options;
- вход с 10 неверными паролями → временная блокировка;
- `/private/<чужой пользователь>/…` → 403;
- `journalctl -u goosko-web` без traceback'ов;
- юнит systemd: `systemd-analyze security goosko-web` (NoNewPrivileges,
  ProtectSystem=strict включены; для camera/grab могут понадобиться
  дополнительные разрешения — добавляйте точечно).
