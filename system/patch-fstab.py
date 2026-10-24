#!/usr/bin/env python3
"""Добавляет noatime для корневого раздела (меньше лишних записей)."""

import os
import shutil
import sys
import time

FSTAB = "/etc/fstab"


def main():
    if os.geteuid() != 0:
        print("Ошибка: нужен root", file=sys.stderr)
        return 1

    with open(FSTAB, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    changed = False
    result = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            result.append(line)
            continue

        fields = stripped.split()
        if len(fields) >= 4 and fields[1] == "/":
            options = fields[3].split(",")
            if "noatime" not in options:
                options.append("noatime")
                fields[3] = ",".join(options)
                result.append("\t".join(fields) + "\n")
                changed = True
                continue
        result.append(line)

    if not changed:
        print("fstab: noatime уже настроен")
        return 0

    backup = f"{FSTAB}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(FSTAB, backup)
    with open(FSTAB, "w", encoding="utf-8") as fh:
        fh.writelines(result)
    print(f"fstab: добавлен noatime (резервная копия {backup})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
