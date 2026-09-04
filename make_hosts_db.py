#!/usr/bin/env python3
"""
make_hosts_db.py — готовит hosts.db рядом с собой (для main.pyw
или для упаковки в .exe через --add-data "hosts.db;.").

Все файлы читаются и создаются ТОЛЬКО в папке скрипта, откуда бы
и как бы его ни запускали — пути указывать не нужно:

    py make_hosts_db.py               # hosts.txt -> hosts.db
    py make_hosts_db.py мойсписок.txt # свой файл списка
    py make_hosts_db.py --password    # ещё и задать пароль администратора
"""
import sys
import os
import re
import sqlite3
import hashlib
import secrets
import getpass

PBKDF2_ITERATIONS = 100_000
SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""
NAME_OK = re.compile(r"[A-Za-z0-9._\-]+\Z")


def resolve(name: str) -> str:
    """Путь к файлу РЯДОМ СО СКРИПТОМ, независимо от папки запуска."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name)


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               salt, PBKDF2_ITERATIONS).hex()


def main():
    args = [a for a in sys.argv[1:] if a != "--password"]
    need_password = "--password" in sys.argv[1:]

    src = resolve(args[0] if args else "hosts.txt")
    out = resolve("hosts.db")

    if not os.path.exists(src):
        sys.exit(f"Не найден список: {src}\n"
                 f"Создайте hosts.txt рядом со скриптом — по узлу в строке.")
    if os.path.exists(out):
        try:
            os.remove(out)
        except PermissionError:
            sys.exit(f"{out} занят другой программой — закройте её и повторите.")

    with open(src, encoding="utf-8-sig") as f:
        hosts = [ln.strip() for ln in f if ln.strip()]
    if not hosts:
        sys.exit(f"В {src} нет ни одного узла.")
    странные = [h for h in hosts if not NAME_OK.fullmatch(h)]
    if странные:
        print("Предупреждение — подозрительные имена:", ", ".join(странные))

    conn = sqlite3.connect(out)
    conn.executescript(SCHEMA)
    conn.executemany("INSERT OR IGNORE INTO hosts(name) VALUES (?)",
                     [(h,) for h in hosts])
    if need_password:
        while True:
            pw = getpass.getpass("Пароль администратора: ")
            if len(pw) < 4:
                print("Минимум 4 символа."); continue
            if pw != getpass.getpass("Повторите: "):
                print("Пароли не совпадают."); continue
            salt = secrets.token_bytes(16)
            conn.execute("INSERT OR REPLACE INTO settings(key, value) "
                         "VALUES ('admin', ?)",
                         (salt.hex() + ":" + hash_password(pw, salt),))
            break
    conn.commit()
    conn.close()
    print(f"Готово: {out} ({len(hosts)} узлов)")

if __name__ == "__main__":
    main()