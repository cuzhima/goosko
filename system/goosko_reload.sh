#!/usr/bin/env bash
#
# goosko_reload.sh — перезапуск сайта GOOSKO.ONLINE при поломке или изменениях
#
# Порядок работы:
#   1. Проверяет зависимости и git-репо в /home/andrey/goosko-site
#   2. Делает systemctl restart (или start) goosko-web
#   3. Ждёт, пока /healthz вернёт ok:true (до 60 с)
#   4. Сравнивает sha из /healthz с текущим git HEAD
#   5. Делает systemctl reload angie (если Angie жива)
#   6. Проверяет цепочку: Flask напрямую и через Angie (Host: goosko.online)
#
# Запускать с sudo (нужен systemctl):
#   sudo /home/andrey/goosko-site/system/goosko_reload.sh
# или скопировать в /usr/local/sbin/goosko_reload.sh и запускать оттуда.

set -euo pipefail

GOOSKO_SITE="/home/andrey/goosko-site"
HEALTH_URL="http://127.0.0.1:5000/healthz"
ANGIE_URL="http://localhost:80/"
ANGIE_HOST="goosko.online"
MAX_WAIT=60
LOG_DIR="/var/log/goosko"
LOG_FILE="$LOG_DIR/goosko-reload.log"

mkdir -p "$LOG_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

die() {
    log "ОШИБКА: $*"
    exit 1
}

check_deps() {
    command -v git   >/dev/null || die "git не найден"
    command -v curl  >/dev/null || die "curl не найден"
    command -v systemctl >/dev/null || die "systemctl не найден"
    [ -d "$GOOSKO_SITE/.git" ] || die "git-репо не найден в $GOOSKO_SITE"
}

get_git_sha() {
    git -C "$GOOSKO_SITE" rev-parse --short HEAD
}

get_health_sha() {
    curl -sS --max-time 10 "$HEALTH_URL" 2>/dev/null \
        | python3 -c 'import sys,json; print(json.load(sys.stdin).get("sha",""))' 2>/dev/null \
        || echo ""
}

health_is_ok() {
    curl -sS --max-time 5 "$HEALTH_URL" 2>/dev/null | grep -q '"ok":true'
}

wait_for_health() {
    local elapsed=0
    while [ "$elapsed" -lt "$MAX_WAIT" ]; do
        if health_is_ok; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    return 1
}

verify_chain() {
    local ok=1

    # 1. Прямой доступ к Flask
    if health_is_ok; then
        log "Прямой доступ к Flask (127.0.0.1:5000/healthz): OK"
    else
        log "Прямой доступ к Flask: FAIL"
        ok=0
    fi

    # 2. Через Angie с Host goosko.online
    if curl -sS --max-time 10 -H "Host: $ANGIE_HOST" "$ANGIE_URL" 2>/dev/null | grep -q '"ok":true'; then
        log "Через Angie (Host: $ANGIE_HOST): OK"
    else
        log "Через Angie (Host: $ANGIE_HOST): FAIL"
        ok=0
    fi

    return $ok
}

main() {
    check_deps

    local BEFORE_SHA AFTER_SHA HEALTH_SHA
    BEFORE_SHA=$(get_git_sha)
    log "Текущий git HEAD: $BEFORE_SHA"

    # Проверяем/запускаем сервис
    if systemctl is-active --quiet goosko-web; then
        log "goosko-web активен — делаем restart"
    else
        log "goosko-web НЕ активен — делаем start"
        sudo systemctl start goosko-web || die "не удалось запустить goosko-web"
    fi

    # Перезапуск (требуется после любых правок app.py — старый код остаётся в памяти)
    sudo systemctl restart goosko-web || die "не удалось перезапустить goosko-web"

    # Ждём, пока gunicorn поднимется
    if ! wait_for_health; then
        die "goosko-web не поднялся за $MAX_WAIT сек — смотри: journalctl -u goosko-web -f"
    fi

    # Проверяем, что в памяти сел именно свежий код
    AFTER_SHA=$(get_git_sha)
    log "git HEAD после рестарта: $AFTER_SHA"

    HEALTH_SHA=$(get_health_sha)
    if [ -z "$HEALTH_SHA" ]; then
        die "не удалось прочитать sha из $HEALTH_URL"
    fi
    if [ "$HEALTH_SHA" != "$AFTER_SHA" ]; then
        die "sha в /healthz ($HEALTH_SHA) не совпадает с git HEAD ($AFTER_SHA) — возможен старый код в памяти"
    fi
    log "/healthz sha совпадает с git HEAD: $HEALTH_SHA"

    # reload Angie (конфиги в /etc/angie/http.d/*.conf)
    if systemctl is-active --quiet angie; then
        sudo systemctl reload angie || log "ВНИМАНИЕ: reload angie не удался (продолжаем)"
        log "Angie перезагружена"
    else
        log "Angie не активна — reload пропущен"
    fi

    # Финальная проверка цепочки
    if ! verify_chain; then
        die "проверка цепочки не пройдена"
    fi

    log "ГОТОВО: сайт перезапущен и проверен (HEAD: $AFTER_SHA)"
}

main "$@"
