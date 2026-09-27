#!/usr/bin/env bash
# Резервная копия БД пользователей и хранилища файлов.
# Копии складываются в BACKUP_DIR (по умолчанию /var/backups/goosko),
# хранятся последние KEEP дней.
#
# Cron-пример (от root или goosko):
#   15 3 * * * /opt/goosko-online/deploy/backup.sh >> /var/log/goosko-backup.log 2>&1

set -euo pipefail

APP_DIR=${APP_DIR:-/opt/goosko-online}
ENV_FILE=${ENV_FILE:-/etc/goosko/goosko.env}
BACKUP_DIR=${BACKUP_DIR:-/var/backups/goosko}
KEEP_DAYS=${KEEP_DAYS:-14}

# Подтягиваем пути из env-файла, если он есть
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a; source "$ENV_FILE"; set +a
fi

DB_PATH=${DB_PATH:-$APP_DIR/users.db}
STORAGE_DIR=${STORAGE_DIR:-/var/www/storage}

STAMP=$(date +%Y%m%d_%H%M%S)
OUT="$BACKUP_DIR/$STAMP"
mkdir -p "$OUT"
umask 077

# 1) SQLite — горячий бэкап через .backup (консистентно при WAL)
if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$DB_PATH" ".backup '$OUT/users.db'"
else
    # запасной вариант: vacuum into file того же эффекта не даёт при записи,
    # поэтому копируем и db, и wal-файлы атомарно через tar
    tar -C "$(dirname "$DB_PATH")" -cf "$OUT/users_db.tar" \
        --warning=no-file-changed \
        "$(basename "$DB_PATH")" "$(basename "$DB_PATH")"-wal "$(basename "$DB_PATH")"-shm 2>/dev/null || true
fi

# 2) Хранилище (без .part-файлов nedозагруженных)
tar -C "$(dirname "$STORAGE_DIR")" -czf "$OUT/storage.tar.gz" \
    --exclude='*.part' --warning=no-file-changed \
    "$(basename "$STORAGE_DIR")" 2>/dev/null || true

# 3) Права и ротация
chmod -R go-rwx "$OUT"
find "$BACKUP_DIR" -maxdepth 1 -type d -mtime +"$KEEP_DAYS" -name '2*' \
    -exec rm -rf {} +

echo "$(date -Is) backup done: $OUT ($(du -sh "$OUT" | cut -f1))"
