#!/usr/bin/env python3
"""
Лог-анализатор: читает лог-файл и показывает короткую сводку.

Что умеет:
  * считает строки по уровням (DEBUG / INFO / WARNING / ERROR / CRITICAL);
  * показывает период, который покрывает лог;
  * находит самые частые ошибки (похожие сообщения группируются);
  * показывает самые частые IP-адреса;
  * считает ошибки по часам;
  * может вывести результат в JSON.

Примеры:
  python log_analyzer.py sample.log
  python log_analyzer.py sample.log --top 5
  python log_analyzer.py sample.log --json > report.json
  cat sample.log | python log_analyzer.py -
"""

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime

LEVEL_RE = re.compile(
    r"\b(DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|CRITICAL|FATAL)\b", re.IGNORECASE
)
TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}):(\d{2}):(\d{2})")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
NUM_RE = re.compile(r"(?<![A-Za-z])\d+")

# Приводим разные написания уровней к одному виду
LEVEL_ALIASES = {
    "WARN": "WARNING",
    "ERR": "ERROR",
    "FATAL": "CRITICAL",
    "NOTICE": "INFO",
}
ERROR_LEVELS = {"ERROR", "CRITICAL"}


def normalize_level(raw):
    level = raw.upper()
    return LEVEL_ALIASES.get(level, level)


def normalize_message(line):
    """Убираем время, уровень, IP и числа, чтобы однотипные ошибки считались вместе."""
    text = TS_RE.sub("", line)
    text = LEVEL_RE.sub("", text, count=1)
    text = IP_RE.sub("<IP>", text)
    text = HEX_RE.sub("<HEX>", text)
    text = NUM_RE.sub("<N>", text)
    text = re.sub(r"[\[\]\-:]+", " ", text)
    return " ".join(text.split())


def analyze(lines):
    levels = Counter()
    errors = Counter()
    ips = Counter()
    errors_by_hour = Counter()
    timestamps = []
    total = 0
    no_level = 0

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        total += 1

        ts_match = TS_RE.search(line)
        ts = None
        if ts_match:
            date, hh, mm, ss = ts_match.groups()
            try:
                ts = datetime.strptime(f"{date} {hh}:{mm}:{ss}", "%Y-%m-%d %H:%M:%S")
                timestamps.append(ts)
            except ValueError:
                ts = None

        for ip in IP_RE.findall(line):
            ips[ip] += 1

        level_match = LEVEL_RE.search(line)
        if not level_match:
            no_level += 1
            continue

        level = normalize_level(level_match.group(1))
        levels[level] += 1

        if level in ERROR_LEVELS:
            errors[normalize_message(line)] += 1
            if ts:
                errors_by_hour[ts.strftime("%Y-%m-%d %H:00")] += 1

    return {
        "total_lines": total,
        "lines_without_level": no_level,
        "levels": dict(levels),
        "first_timestamp": min(timestamps).isoformat(sep=" ") if timestamps else None,
        "last_timestamp": max(timestamps).isoformat(sep=" ") if timestamps else None,
        "top_errors": errors,
        "top_ips": ips,
        "errors_by_hour": dict(sorted(errors_by_hour.items())),
    }


def print_report(result, top):
    print("=" * 50)
    print(" ОТЧЁТ ПО ЛОГУ")
    print("=" * 50)
    print(f"Всего строк:          {result['total_lines']}")
    print(f"Без уровня (мусор):   {result['lines_without_level']}")
    if result["first_timestamp"]:
        print(f"Период:               {result['first_timestamp']}  ->  {result['last_timestamp']}")

    print("\nПо уровням:")
    if result["levels"]:
        for level, count in sorted(result["levels"].items(), key=lambda x: -x[1]):
            print(f"  {level:<9} {count}")
    else:
        print("  уровни не найдены")

    print(f"\nТоп-{top} частых ошибок:")
    if result["top_errors"]:
        for message, count in result["top_errors"].most_common(top):
            short = message if len(message) <= 80 else message[:77] + "..."
            print(f"  {count:>4}x  {short}")
    else:
        print("  ошибок нет")

    print(f"\nТоп-{top} IP-адресов:")
    if result["top_ips"]:
        for ip, count in result["top_ips"].most_common(top):
            print(f"  {count:>4}x  {ip}")
    else:
        print("  IP-адреса не найдены")

    print("\nОшибки по часам:")
    if result["errors_by_hour"]:
        peak = max(result["errors_by_hour"].values())
        for hour, count in result["errors_by_hour"].items():
            bar = "#" * max(1, round(count / peak * 20))
            print(f"  {hour}  {bar} {count}")
    else:
        print("  нет данных")


def to_json(result, top):
    data = dict(result)
    data["top_errors"] = dict(result["top_errors"].most_common(top))
    data["top_ips"] = dict(result["top_ips"].most_common(top))
    return json.dumps(data, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Простой анализатор лог-файлов.")
    parser.add_argument("file", help="путь к лог-файлу или '-' для чтения из stdin")
    parser.add_argument("--top", type=int, default=5, help="сколько строк показывать в топах (по умолчанию 5)")
    parser.add_argument("--json", action="store_true", help="вывести результат в формате JSON")
    args = parser.parse_args()

    try:
        if args.file == "-":
            lines = sys.stdin.read().splitlines()
        else:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
    except FileNotFoundError:
        sys.exit(f"Файл не найден: {args.file}")
    except OSError as e:
        sys.exit(f"Не удалось прочитать файл: {e}")

    result = analyze(lines)

    if args.json:
        print(to_json(result, args.top))
    else:
        print_report(result, args.top)


if __name__ == "__main__":
    main()
