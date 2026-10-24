#!/usr/bin/env python3
"""Убирает жёстко заданный Host/Proto из Angie, чтобы локальный вход работал."""

import os
import shutil
import subprocess
import sys
import time

CONF = "/etc/angie/http.d/goosko.conf"

REPLACEMENTS = [
    (
        "proxy_set_header Host goosko.online;",
        "proxy_set_header Host $http_host;",
    ),
    (
        "proxy_set_header X-Forwarded-Host goosko.online;",
        "proxy_set_header X-Forwarded-Host $http_host;",
    ),
    (
        "proxy_set_header X-Forwarded-Proto https;",
        "proxy_set_header X-Forwarded-Proto $goosko_proto;",
    ),
    (
        "proxy_set_header X-Forwarded-Proto $scheme;",
        "proxy_set_header X-Forwarded-Proto $goosko_proto;",
    ),
    (
        "return 302 https://goosko.online/;",
        "return 302 /;",
    ),
]


def main():
    if os.geteuid() != 0:
        print("Ошибка: нужен root", file=sys.stderr)
        return 1

    if not os.path.isfile(CONF):
        print(f"Не найден {CONF}", file=sys.stderr)
        return 1

    with open(CONF, "r", encoding="utf-8") as fh:
        original = fh.read()

    text = original
    for old, new in REPLACEMENTS:
        text = text.replace(old, new)

    if text == original:
        print("Angie: конфигурация уже исправлена")
        return 0

    backup = f"{CONF}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(CONF, backup)
    print(f"Angie: резервная копия {backup}")

    with open(CONF, "w", encoding="utf-8") as fh:
        fh.write(text)

    if shutil.which("angie"):
        result = subprocess.run(
            ["angie", "-t"], capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            shutil.copy2(backup, CONF)
            print("Angie: проверка не прошла, изменения отменены", file=sys.stderr)
            print((result.stdout or "") + (result.stderr or ""), file=sys.stderr)
            return 1
        print("Angie: конфигурация корректна")

    return 0


if __name__ == "__main__":
    sys.exit(main())
