#!/usr/bin/env python3
"""
Диагностика сети — визуализация МАРШРУТА (tracert/traceroute) до узлов.
Каждый хоп: имя, IP-адрес, статус, отклик. Узлы без связи поднимаются
наверх списка и выводятся в сводке сверху.

Список узлов и пароль администратора хранятся в базе SQLite. База ищется:
    1) hosts.db рядом с программой;
    2) C:\\ProgramData\\pingMonitorGUI\\hosts.db;
    3) если нигде нет — создаётся (для .exe — из шаблона, упакованного
       внутрь через --add-data "hosts.db;.").
Изменение списка — только после ввода пароля (кнопка 🔒). Пароль хранится
в базе как PBKDF2-хэш, поэтому «переезжает» вместе с файлом базы.

Работает и на Windows 7 (там нужен PyQt5), и на Windows 8/10/11
(PyQt6): подходящая библиотека выбирается автоматически при запуске.
Для Windows 7 собирать Python 3.8 + PyQt5, для новых систем — любой
новый Python + PyQt6; код один и тот же.

Требования (выберите один вариант):
    pip install PyQt6                 # Windows 8/10/11
    pip install PyQt5                 # чтобы работал и Windows 7

Запуск:
    main.pyw
"""

import sys
import os
import re
import sqlite3
import hashlib
import secrets
import shutil
import socket
import platform
import subprocess
from datetime import datetime

# ---- Qt: PyQt6 для Windows 8/10/11; PyQt5 — чтобы работал и Windows 7 ----
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QListWidget, QListWidgetItem, QScrollArea,
        QFrame, QSpinBox, QInputDialog, QMessageBox, QLineEdit
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QColor
except ImportError:
    try:
        from PyQt5.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QLabel, QPushButton, QListWidget, QListWidgetItem, QScrollArea,
            QFrame, QSpinBox, QInputDialog, QMessageBox, QLineEdit
        )
        from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
        from PyQt5.QtGui import QColor
        # В PyQt5 перечисления не вложены, как в PyQt6; алиасы позволяют
        # не менять весь остальной код:
        Qt.AlignmentFlag = Qt            # Qt.AlignmentFlag.AlignRight -> Qt.AlignRight
        Qt.ItemDataRole = Qt             # Qt.ItemDataRole.UserRole   -> Qt.UserRole
        QMessageBox.StandardButton = QMessageBox
        QLineEdit.EchoMode = QLineEdit
    except ImportError as e:
        msg = ("Не найдена библиотека PyQt5/PyQt6.\n\n" + str(e))
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, msg, "Маршрут сети", 0x10)
        except Exception:
            print(msg)
        sys.exit(1)

# ==== УЗЛЫ ПО УМОЛЧАНИЮ (пока администратор не задал свой список) ====
DEFAULT_HOSTS = [
    "HOST1",
    "HOST2",
    "HOST3",
]

APP_NAME = "pingMonitorGUI"
# имя узла: латиница, цифры, точка, дефис, подчёркивание (домен или IPv4)
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._\-]+$")

MIN_PASSWORD_LEN = 4
PBKDF2_ITERATIONS = 100_000

MAX_HOPS = 30
HOP_TIMEOUT_MS = 1500

# ==== РАЗМЕР ШРИФТА ====
FONT_SIZE_BASE = 16
FONT_SIZE_TITLE = 22
FONT_SIZE_HOST_NAME = 22
FONT_SIZE_SMALL = 14
FONT_SIZE_LATENCY = 16


# ---------------------------------------------------------------------------
#  ХРАНЕНИЕ: SQLite (узлы + пароль администратора)
# ---------------------------------------------------------------------------

def app_dir() -> str:
    """Папка с программой (.pyw или .exe)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(sys.argv[0]))


def db_path() -> str:
    base = os.environ.get("PROGRAMDATA") or os.path.expanduser("~")
    return os.path.join(base, APP_NAME, "hosts.db")


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


def _create_db(path: str):
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.executemany("INSERT OR IGNORE INTO hosts(name) VALUES (?)",
                     [(h,) for h in DEFAULT_HOSTS])
    conn.commit()
    conn.close()


def init_db() -> str:
    """Рабочая база: рядом с программой -> ProgramData -> создать новую."""
    local = os.path.join(app_dir(), "hosts.db")
    if os.path.exists(local):
        return local
    path = db_path()
    if os.path.exists(path):
        return path
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if getattr(sys, "frozen", False):     # шаблон, упакованный в .exe
            tpl = os.path.join(getattr(sys, "_MEIPASS", ""), "hosts.db")
            if os.path.exists(tpl):
                shutil.copyfile(tpl, path)
                return path
        _create_db(path)
        return path
    except OSError:
        return ":memory:"   # файл недоступен — работаем без сохранения


DB_PATH = init_db()
_MEM_CONN = None


def _connect():
    """Соединение с базой. Если записать файл негде, держим один
    In-Memory-коннект: мониторинг работает, сохранение — нет."""
    global _MEM_CONN
    if DB_PATH == ":memory:":
        if _MEM_CONN is None:
            _MEM_CONN = sqlite3.connect(":memory:")
            _MEM_CONN.executescript(SCHEMA)
        return _MEM_CONN
    return sqlite3.connect(DB_PATH)


def load_hosts():
    """(список узлов, текст ошибки). Ошибку не глотаем: молчаливая
    подстановка списка по умолчанию маскирует проблемы с базой."""
    try:
        conn = _connect()
        try:
            rows = conn.execute("SELECT name FROM hosts ORDER BY id").fetchall()
        finally:
            if DB_PATH != ":memory:":
                conn.close()
        return [r[0].strip() for r in rows
                if isinstance(r[0], str) and r[0].strip()], None
    except sqlite3.Error as e:
        return [], f"Не удалось прочитать базу:\n{DB_PATH}\n\n{e}"


def replace_hosts(hosts: list):
    """Возвращает None при успехе или текст ошибки."""
    try:
        conn = _connect()
        try:
            with conn:   # транзакция: либо весь список, либо ничего
                conn.execute("DELETE FROM hosts")
                conn.executemany("INSERT INTO hosts(name) VALUES (?)",
                                 [(h,) for h in hosts])
        finally:
            if DB_PATH != ":memory:":
                conn.close()
        return None
    except (sqlite3.Error, OSError) as e:
        return f"Не удалось сохранить список:\n{DB_PATH}\n\n{e}"


# ---- пароль администратора (PBKDF2, в открытом виде не хранится) ----

def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               salt, PBKDF2_ITERATIONS).hex()


def get_admin_record():
    """(salt_hex, hash_hex), если пароль установлен, иначе None."""
    try:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT value FROM settings WHERE key='admin'").fetchone()
        finally:
            if DB_PATH != ":memory:":
                conn.close()
        if row:
            salt_hex, sep, hash_hex = row[0].partition(":")
            if sep and salt_hex and hash_hex:
                return salt_hex, hash_hex
    except (sqlite3.Error, OSError):
        pass
    return None


def set_admin_password(password: str):
    salt = secrets.token_bytes(16)
    conn = _connect()
    try:
        with conn:
            conn.execute("INSERT OR REPLACE INTO settings(key, value) "
                         "VALUES ('admin', ?)",
                         (salt.hex() + ":" + _hash_password(password, salt),))
    finally:
        if DB_PATH != ":memory:":
            conn.close()


def check_admin_password(password: str) -> bool:
    rec = get_admin_record()
    if rec is None:
        return False
    calc = _hash_password(password, bytes.fromhex(rec[0]))
    return secrets.compare_digest(calc, rec[1])


# ---------------------------------------------------------------------------
#  ЛОГИКА ТРАССИРОВКИ
# ---------------------------------------------------------------------------

def resolve_ip(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.error:
        return "—"


def decode_output(raw: bytes) -> str:
    """Консоль Windows в русской локали обычно пишет в cp866."""
    for encoding in ("utf-8", "cp866", "cp1251"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


HOP_RE = re.compile(r'^\s*(\d{1,3})\s+(.+)$')
IPV4_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
NAME_IP_RE = re.compile(
    r'([^\s\[\(]+)\s*[\[\(]\s*(\d{1,3}(?:\.\d{1,3}){3})\s*[\]\)]'
)
LATENCY_RE = re.compile(
    r'(?:^|(?<=\s))(<?)\s*(\d+(?:[.,]\d+)?)\s*(?:мс|ms|msec)(?=\s|$)',
    re.IGNORECASE,
)
RESOLVE_FAIL_RE = re.compile(
    r"удается разрешить|unable to resolve|cannot resolve|unknown host",
    re.IGNORECASE,
)


def parse_traceroute_line(line: str):
    m = HOP_RE.match(line)
    if not m:
        return None
    rest = m.group(2).strip()

    hostname = ip = None
    pair = NAME_IP_RE.search(rest)
    if pair:
        hostname, ip = pair.group(1), pair.group(2)
    else:
        bare = IPV4_RE.search(rest)
        if bare:
            ip = bare.group(1)

    times = []
    for lt, num in LATENCY_RE.findall(rest):
        value = float(num.replace(",", "."))
        if lt and value <= 1:
            value = 0.5
        times.append(value)

    latency = sum(times) / len(times) if times else None
    status = "ok" if (ip or times) else "timeout"

    return {
        "hop": int(m.group(1)),
        "ip": ip or "—",
        "hostname": hostname or ("узел не отвечает" if status == "timeout" else "—"),
        "latency": latency,
        "status": status,
    }


def diagnostic_from_output(lines: list, target: str) -> str:
    """Человекочитаемая причина, почему хопы не получены."""
    if not lines:
        return "утилита трассировки не вернула никакого вывода"
    if RESOLVE_FAIL_RE.search(" ".join(lines)):
        return (f"имя «{target}» не удалось преобразовать в IP-адрес — "
                f"проверьте его командой ping/nslookup или укажите IP напрямую")
    return f"утилита сообщила: «{lines[-1]}»"


def run_traceroute(target: str, worker=None, on_hop=None):
    system = platform.system().lower()

    if system == "windows":
        windir = os.environ.get("SystemRoot", r"C:\Windows")
        exe = os.path.join(windir, "System32", "tracert.exe")
        if not os.path.exists(exe):
            exe = "tracert"
        cmd = [exe, "-h", str(MAX_HOPS), "-w", str(HOP_TIMEOUT_MS), target]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        cmd = ["traceroute", "-m", str(MAX_HOPS), "-w", "1", target]
        creationflags = 0

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # ошибки не теряются
            creationflags=creationflags,
        )
    except OSError as e:
        return [], f"не удалось запустить {cmd[0]}: {e}"

    if worker is not None:
        worker.current_proc = proc

    hops, lines = [], []
    try:
        for raw_line in proc.stdout:
            if worker is not None and worker._stopped:
                break
            line = decode_output(raw_line).strip()
            if not line:
                continue
            if len(lines) < 5:
                lines.append(line)
            hop = parse_traceroute_line(line)
            if hop:
                hops.append(hop)
                if on_hop is not None:
                    on_hop(hop)
            if len(hops) >= MAX_HOPS:
                break
    finally:
        if worker is not None:
            worker.current_proc = None
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass

    if not hops:
        return [], diagnostic_from_output(lines, target)
    return hops, None


class TraceWorker(QThread):
    hop_ready = pyqtSignal(str, dict)
    host_finished = pyqtSignal(str, bool, str)

    def __init__(self, hosts):
        super().__init__()
        self.hosts = hosts
        self.current_proc = None
        self._stopped = False

    def stop(self):
        self._stopped = True
        proc = self.current_proc
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass

    def run(self):
        for target in self.hosts:
            if self._stopped:
                return
            hops, error_text = run_traceroute(
                target,
                worker=self,
                on_hop=lambda hop, t=target: self.hop_ready.emit(t, hop),
            )
            if self._stopped:
                return

            reached = False
            target_ip = resolve_ip(target)
            target_lower = target.lower()
            for hop in hops:
                if target_ip != "—" and hop["ip"] == target_ip:
                    reached = True
                    break
                name = (hop["hostname"] or "").lower()
                if name == target_lower or name.startswith(target_lower + "."):
                    reached = True
                    break

            self.host_finished.emit(target, reached, error_text or "")


# ---------------------------------------------------------------------------
#  СТИЛИ
# ---------------------------------------------------------------------------

COLOR_BG_BASE = "#10141a"
COLOR_BG_PANEL = "#171d26"
COLOR_BG_CARD = "#1e2530"
COLOR_BORDER = "#2a3341"
COLOR_TEXT_PRIMARY = "#e8ecf2"
COLOR_TEXT_SECONDARY = "#7c8798"
COLOR_OK = "#35d488"
COLOR_DOWN = "#ff5c72"
COLOR_WARN = "#f5a623"
COLOR_BRAND = "#4fb2ff"

QSS = f"""
QMainWindow {{
    background-color: {COLOR_BG_BASE};
}}
/* Диалоги: без этого их фон системный светло-серый,
   и светлый текст из правила QWidget не виден */
QDialog, QMessageBox, QInputDialog {{
    background-color: {COLOR_BG_PANEL};
}}
QWidget {{
    color: {COLOR_TEXT_PRIMARY};
    font-family: "Segoe UI";
    font-size: {FONT_SIZE_BASE}px;
}}
QLineEdit {{
    background-color: {COLOR_BG_CARD};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 6px 8px;
    selection-background-color: {COLOR_BRAND};
    selection-color: {COLOR_BG_BASE};
}}
QLineEdit:focus {{
    border: 1px solid {COLOR_BRAND};
}}
QToolTip {{
    background-color: {COLOR_BG_CARD};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    padding: 4px 6px;
}}
#Sidebar {{
    background-color: {COLOR_BG_PANEL};
    border-right: 1px solid {COLOR_BORDER};
}}
#TopBar {{
    background-color: {COLOR_BG_PANEL};
    border-bottom: 1px solid {COLOR_BORDER};
}}
#AppTitle {{
    font-size: {FONT_SIZE_TITLE}px;
    font-weight: 600;
}}
#SummaryBar {{
    padding: 10px 18px;
    font-weight: 600;
}}
#SummaryBar[level="bad"] {{
    background-color: #3a1620;
    color: #ff8b99;
    border-bottom: 1px solid #6b2433;
}}
#SummaryBar[level="ok"] {{
    background-color: #12271a;
    color: #7fe0a8;
    border-bottom: 1px solid #1f4d31;
}}
#SummaryBar[level="wait"] {{
    background-color: {COLOR_BG_PANEL};
    color: {COLOR_TEXT_SECONDARY};
    border-bottom: 1px solid {COLOR_BORDER};
}}
QListWidget {{
    background: transparent;
    border: none;
    outline: none;
    padding: 6px;
}}
QListWidget::item {{
    background-color: {COLOR_BG_CARD};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    padding: 10px;
    margin: 4px 2px;
}}
QListWidget::item:selected {{
    border: 1px solid {COLOR_BRAND};
    background-color: #202b3a;
}}
QPushButton {{
    background-color: {COLOR_BG_CARD};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 7px 14px;
}}
QPushButton:hover {{
    border: 1px solid {COLOR_BRAND};
}}
QPushButton:pressed {{
    background-color: #202b3a;
}}
QSpinBox {{
    background-color: {COLOR_BG_CARD};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 4px 6px;
}}
QScrollArea {{
    border: none;
    background: transparent;
}}
#HopCard {{
    background-color: {COLOR_BG_CARD};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
}}
#HopCard[status="ok"] {{
    border-left: 3px solid {COLOR_OK};
}}
#HopCard[status="timeout"] {{
    border-left: 3px solid {COLOR_WARN};
}}
#Connector {{
    background-color: {COLOR_BORDER};
}}
QLabel[role="mono"] {{
    font-family: "Consolas";
}}
QLabel[role="secondary"] {{
    color: {COLOR_TEXT_SECONDARY};
}}
QLabel[role="dot-ok"] {{
    color: {COLOR_OK};
    font-size: {FONT_SIZE_BASE + 2}px;
}}
QLabel[role="dot-warn"] {{
    color: {COLOR_WARN};
    font-size: {FONT_SIZE_BASE + 2}px;
}}
"""


def refresh_style(widget):
    widget.style().unpolish(widget)
    widget.style().polish(widget)


# ---------------------------------------------------------------------------
#  ЭЛЕМЕНТЫ UI
# ---------------------------------------------------------------------------

class HopCard(QFrame):
    def __init__(self, hop: dict):
        super().__init__()
        self.setObjectName("HopCard")
        self.setProperty("status", hop["status"])

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)

        num = QLabel(f'{hop["hop"]:>2}')
        num.setProperty("role", "secondary")
        num.setFixedWidth(26)
        layout.addWidget(num)

        dot = QLabel("●")
        dot.setProperty("role", "dot-ok" if hop["status"] == "ok" else "dot-warn")
        dot.setFixedWidth(18)
        layout.addWidget(dot)

        text_box = QVBoxLayout()
        text_box.setSpacing(2)
        name = QLabel(hop["hostname"])
        name.setStyleSheet("font-weight: 600;")
        text_box.addWidget(name)
        ip = QLabel(hop["ip"])
        ip.setProperty("role", "mono")
        ip.setStyleSheet(f"color: {COLOR_TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px;")
        text_box.addWidget(ip)
        layout.addLayout(text_box, stretch=1)

        if hop["latency"] is None:
            latency_text = "нет ответа"
        elif hop["latency"] < 1:
            latency_text = "<1 мс"
        else:
            latency_text = f'{hop["latency"]:.0f} мс'
        lat = QLabel(latency_text)
        lat.setProperty("role", "mono")
        lat.setStyleSheet(f"font-size: {FONT_SIZE_LATENCY}px;")
        lat.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(lat)

        refresh_style(self)
        refresh_style(dot)


class Connector(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("Connector")
        self.setFixedWidth(2)
        self.setFixedHeight(14)


# ---------------------------------------------------------------------------
#  ГЛАВНОЕ ОКНО
# ---------------------------------------------------------------------------

class RouteMonitorWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Маршрут сети")
        self.resize(920, 600)

        self.hosts, load_error = load_hosts()
        if load_error:
            QMessageBox.critical(None, "База данных", load_error)

        self._unlocked = False
        self.worker = None
        self.timer = QTimer()
        self.timer.timeout.connect(self.start_trace)

        self.host_data = {h: {"hops": [], "reached": None, "done": False, "error": ""}
                          for h in self.hosts}
        self._prev_state = {h: None for h in self.hosts}
        self._ip_cache = {}
        self.current_host = self.hosts[0] if self.hosts else None

        self._build_ui()
        self.start_trace()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        top_bar = QWidget()
        top_bar.setObjectName("TopBar")
        top = QHBoxLayout(top_bar)
        top.setContentsMargins(18, 14, 18, 14)

        title = QLabel("Маршрут сети")
        title.setObjectName("AppTitle")
        top.addWidget(title)
        top.addStretch()

        self.status_label = QLabel("Готово")
        self.status_label.setProperty("role", "secondary")
        top.addWidget(self.status_label)

        top.addSpacing(16)
        top.addWidget(QLabel("Обновлять каждые, сек:"))
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(0, 3600)
        self.interval_spin.setValue(0)
        self.interval_spin.valueChanged.connect(self._on_interval_changed)
        top.addWidget(self.interval_spin)

        self.refresh_btn = QPushButton("Обновить")
        self.refresh_btn.clicked.connect(self.start_trace)
        top.addWidget(self.refresh_btn)

        self.add_btn = QPushButton("＋ Узел")
        self.add_btn.clicked.connect(self._on_add_host)
        top.addWidget(self.add_btn)

        self.del_btn = QPushButton("− Узел")
        self.del_btn.clicked.connect(self._on_del_host)
        top.addWidget(self.del_btn)

        self.pw_btn = QPushButton("🔒")
        self.pw_btn.setFixedWidth(44)
        self.pw_btn.clicked.connect(self._on_password_btn)
        top.addWidget(self.pw_btn)

        root.addWidget(top_bar)

        self.summary_bar = QLabel("")
        self.summary_bar.setObjectName("SummaryBar")
        self.summary_bar.setWordWrap(True)
        root.addWidget(self.summary_bar)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        root.addLayout(body, stretch=1)

        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(240)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(0, 10, 0, 10)

        self.host_list = QListWidget()
        self.host_list.currentItemChanged.connect(self._on_host_selected)
        side.addWidget(self.host_list)
        body.addWidget(sidebar)

        self.route_scroll = QScrollArea()
        self.route_scroll.setWidgetResizable(True)
        self.route_container = QWidget()
        self.route_layout = QVBoxLayout(self.route_container)
        self.route_layout.setContentsMargins(24, 20, 24, 20)
        self.route_layout.setSpacing(0)
        self.route_layout.addStretch()
        self.route_scroll.setWidget(self.route_container)
        body.addWidget(self.route_scroll, stretch=1)

        self._rebuild_sidebar()
        self._update_lock_ui()

    # -- пароль администратора -------------------------------------------

    def _update_lock_ui(self):
        if self._unlocked:
            self.pw_btn.setText("🔓")
            self.pw_btn.setToolTip("Режим администратора включён (до закрытия "
                                   "программы). Нажмите, чтобы сменить пароль.")
        else:
            self.pw_btn.setText("🔒")
            self.pw_btn.setToolTip("Войти в режим администратора / сменить пароль")

    def _ask_new_password(self) -> bool:
        while True:
            pw1, ok = QInputDialog.getText(
                self, "Пароль администратора",
                f"Новый пароль (не менее {MIN_PASSWORD_LEN} символов):",
                QLineEdit.EchoMode.Password)
            if not ok:
                return False
            if len(pw1) < MIN_PASSWORD_LEN:
                QMessageBox.warning(self, "Пароль администратора",
                                    f"Минимум {MIN_PASSWORD_LEN} символов.")
                continue
            pw2, ok = QInputDialog.getText(
                self, "Пароль администратора", "Повторите новый пароль:",
                QLineEdit.EchoMode.Password)
            if not ok:
                return False
            if pw1 != pw2:
                QMessageBox.warning(self, "Пароль администратора",
                                    "Пароли не совпадают.")
                continue
            try:
                set_admin_password(pw1)
            except (sqlite3.Error, OSError) as e:
                QMessageBox.critical(self, "Пароль администратора",
                                     f"Не удалось сохранить пароль:\n{e}")
                return False
            return True

    def _ensure_unlocked(self) -> bool:
        if self._unlocked:
            return True
        if get_admin_record() is None:
            QMessageBox.information(
                self, "Администратор",
                "Пароль администратора ещё не установлен.\n\n"
                "Задайте его сейчас и сообщите только тем, кому разрешено "
                "менять список узлов.")
            if not self._ask_new_password():
                return False
        else:
            while True:
                pw, ok = QInputDialog.getText(
                    self, "Администратор", "Пароль администратора:",
                    QLineEdit.EchoMode.Password)
                if not ok:
                    return False
                if check_admin_password(pw):
                    break
                QMessageBox.warning(self, "Администратор", "Неверный пароль.")
        self._unlocked = True
        self._update_lock_ui()
        return True

    def _on_password_btn(self):
        if get_admin_record() is None:
            if self._ask_new_password():
                self._unlocked = True
                self._update_lock_ui()
            return
        if self._ensure_unlocked():
            self._ask_new_password()   # смена пароля

    # -- добавление / удаление узлов --------------------------------------

    def _on_add_host(self):
        if not self._ensure_unlocked():
            return
        name, ok = QInputDialog.getText(
            self, "Добавить узел", "Имя компьютера или IP-адрес:")
        if not ok:
            return
        name = name.strip()
        if not name:
            return
        if not HOSTNAME_RE.fullmatch(name):
            QMessageBox.warning(
                self, "Добавить узел",
                "Имя может содержать только латинские буквы, цифры,\n"
                "точку, дефис и подчёркивание.")
            return
        if any(h.lower() == name.lower() for h in self.hosts):
            QMessageBox.information(self, "Добавить узел", "Такой узел уже есть в списке.")
            return
        new_hosts = self.hosts + [name]
        err = replace_hosts(new_hosts)
        if err:
            QMessageBox.critical(self, "Сохранение", err)
            return
        self.hosts = new_hosts
        self._on_hosts_changed()

    def _on_del_host(self):
        if not self._ensure_unlocked():
            return
        host = self.current_host
        if host is None:
            return
        ans = QMessageBox.question(
            self, "Удалить узел", f"Убрать «{host}» из списка?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if ans != QMessageBox.StandardButton.Yes:
            return
        new_hosts = [h for h in self.hosts if h != host]
        err = replace_hosts(new_hosts)
        if err:
            QMessageBox.critical(self, "Сохранение", err)
            return
        self.hosts = new_hosts
        self._on_hosts_changed()

    def _on_hosts_changed(self):
        if self.current_host not in self.hosts:
            self.current_host = self.hosts[0] if self.hosts else None
        self.host_data = {h: {"hops": [], "reached": None, "done": False, "error": ""}
                          for h in self.hosts}
        self._prev_state = {h: None for h in self.hosts}
        if self.worker is not None and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(2000)
        self._rebuild_sidebar()
        self.start_trace()

    # -- служебное --------------------------------------------------------

    def _resolve_cached(self, host):
        if host not in self._ip_cache:
            ip = resolve_ip(host)
            if ip != "—":
                self._ip_cache[host] = ip
            return ip
        return self._ip_cache[host]

    def _on_interval_changed(self, value):
        if value > 0:
            self.timer.start(value * 1000)
        else:
            self.timer.stop()

    # -- сводка и сортировка ------------------------------------------

    def _update_summary(self):
        down = [h for h in self.hosts
                if self.host_data[h]["done"] and self.host_data[h]["reached"] is False]
        pending = [h for h in self.hosts if not self.host_data[h]["done"]]

        if down:
            shown = down[:5]
            extra = len(down) - len(shown)
            names = ", ".join(shown) + (f" … и ещё {extra}" if extra else "")
            self.summary_bar.setProperty("level", "bad")
            self.summary_bar.setText(
                f"⚠  НЕ ПИНГУЮТСЯ ({len(down)} из {len(self.hosts)}):  {names}"
            )
        elif pending:
            self.summary_bar.setProperty("level", "wait")
            self.summary_bar.setText("Идёт проверка связи…")
        else:
            self.summary_bar.setProperty("level", "ok")
            self.summary_bar.setText(f"✓  Все узлы отвечают ({len(self.hosts)})")
        refresh_style(self.summary_bar)

    def _reorder_sidebar(self):
        lw = self.host_list

        def sort_key(host):
            try:
                order = self.hosts.index(host)
            except ValueError:
                order = 10 ** 9
            d = self.host_data.get(host)
            if d is None or not d["done"]:
                return (1, order)
            return (0 if d["reached"] is False else 2, order)

        items = [lw.item(i) for i in range(lw.count())]
        items.sort(key=lambda it: sort_key(it.data(Qt.ItemDataRole.UserRole)))

        lw.blockSignals(True)
        for pos, item in enumerate(items):
            lw.takeItem(lw.row(item))
            lw.insertItem(pos, item)
        for i in range(lw.count()):
            if lw.item(i).data(Qt.ItemDataRole.UserRole) == self.current_host:
                lw.setCurrentRow(i)
                break
        lw.blockSignals(False)

    def _rebuild_sidebar(self):
        lw = self.host_list
        lw.blockSignals(True)
        lw.clear()
        for h in self.hosts:
            item = QListWidgetItem(h)
            item.setData(Qt.ItemDataRole.UserRole, h)
            lw.addItem(item)
        for i in range(lw.count()):
            h = lw.item(i).data(Qt.ItemDataRole.UserRole)
            self._update_sidebar_dot(h, self.host_data.get(h, {}).get("reached"))
        if self.current_host is not None:
            for i in range(lw.count()):
                if lw.item(i).data(Qt.ItemDataRole.UserRole) == self.current_host:
                    lw.setCurrentRow(i)
                    break
        lw.blockSignals(False)

    # -- цикл обновления ----------------------------------------------

    def start_trace(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.refresh_btn.setEnabled(False)
        self.status_label.setText("Трассировка маршрута...")

        for h in self.hosts:
            self.host_data[h] = {"hops": [], "reached": None, "done": False, "error": ""}
            self._update_sidebar_dot(h, None)

        self.worker = TraceWorker(list(self.hosts))
        self.worker.hop_ready.connect(self._on_hop_ready)
        self.worker.host_finished.connect(self._on_host_finished)
        self.worker.finished.connect(self._on_all_finished)
        self.worker.start()

        self._reorder_sidebar()
        self._update_summary()
        self._render_route(self.current_host)

    def _on_hop_ready(self, host, hop):
        if host not in self.host_data:
            return
        self.host_data[host]["hops"].append(hop)
        if host == self.current_host:
            self._render_route(host)

    def _on_host_finished(self, host, reached, error_text):
        if host not in self.host_data:
            return
        if self._prev_state.get(host) is True and reached is False:
            QApplication.beep()   # был жив — стал молчать (можно удалить)
        self._prev_state[host] = reached

        self.host_data[host]["reached"] = reached
        self.host_data[host]["done"] = True
        self.host_data[host]["error"] = error_text
        self._update_sidebar_dot(host, reached)
        self._reorder_sidebar()
        self._update_summary()
        if host == self.current_host:
            self._render_route(host)

    def _on_all_finished(self):
        self.refresh_btn.setEnabled(True)
        now = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        down = [h for h in self.hosts if self.host_data[h]["reached"] is False]
        if down:
            self.status_label.setText(f"Обновлено: {now}  ·  ⚠ не отвечают: {len(down)}")
        else:
            self.status_label.setText(f"Обновлено: {now}")

    def _update_sidebar_dot(self, host, reached):
        for i in range(self.host_list.count()):
            item = self.host_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == host:
                if reached is None:
                    color, mark, tip = COLOR_TEXT_SECONDARY, "", "проверяется…"
                elif reached:
                    color, mark, tip = COLOR_OK, "", "отвечает"
                else:
                    color, mark, tip = COLOR_DOWN, "  ⚠", "НЕТ СВЯЗИ"
                item.setText(f"●  {host}{mark}")
                item.setToolTip(f"{host}: {tip}")
                item.setForeground(QColor(color))

    def _on_host_selected(self, current, previous):
        if current is None:
            return
        self.current_host = current.data(Qt.ItemDataRole.UserRole)
        self._render_route(self.current_host)

    def _render_route(self, host):
        while self.route_layout.count() > 1:
            item = self.route_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        if host is None:
            empty = QLabel("Список узлов пуст. Добавьте узел кнопкой «＋ Узел».")
            empty.setProperty("role", "secondary")
            self.route_layout.insertWidget(self.route_layout.count() - 1, empty)
            return

        hops = self.host_data[host]["hops"]
        reached = self.host_data[host]["reached"]

        header = QLabel(host)
        header.setStyleSheet(f"font-size: {FONT_SIZE_HOST_NAME}px; font-weight: 600;")
        self.route_layout.insertWidget(self.route_layout.count() - 1, header)

        ip = self._resolve_cached(host)
        sub_text = ("Целевой IP: не определён (имя не резолвится — DNS/hosts)"
                    if ip == "—" else f"Целевой IP: {ip}")
        sub = QLabel(sub_text)
        sub.setProperty("role", "secondary")
        self.route_layout.insertWidget(self.route_layout.count() - 1, sub)

        spacer = QLabel("")
        spacer.setFixedHeight(10)
        self.route_layout.insertWidget(self.route_layout.count() - 1, spacer)

        if not hops:
            if self.host_data[host]["done"]:
                err = self.host_data[host]["error"]
                text = (f"Маршрут не получен: {err}" if err else
                        "Маршрут не получен: утилита tracert/traceroute недоступна "
                        "или не вернула результатов")
            else:
                text = "Трассировка выполняется..."
            waiting = QLabel(text)
            waiting.setProperty("role", "secondary")
            waiting.setWordWrap(True)
            self.route_layout.insertWidget(self.route_layout.count() - 1, waiting)
            return

        for i, hop in enumerate(hops):
            card = HopCard(hop)
            self.route_layout.insertWidget(self.route_layout.count() - 1, card)
            if i < len(hops) - 1:
                row = QHBoxLayout()
                row.setContentsMargins(32, 0, 0, 0)
                row.addWidget(Connector())
                row.addStretch()
                wrap = QWidget()
                wrap.setLayout(row)
                self.route_layout.insertWidget(self.route_layout.count() - 1, wrap)

        if reached is False:
            result = QLabel("⚠ Маршрут не дошёл до узла — обрыв связи на одном из хопов выше")
            result.setStyleSheet(f"color: {COLOR_DOWN}; font-weight: 600; margin-top: 10px;")
            self.route_layout.insertWidget(self.route_layout.count() - 1, result)
        elif reached is True:
            result = QLabel("✓ Маршрут успешно достиг узла")
            result.setStyleSheet(f"color: {COLOR_OK}; font-weight: 600; margin-top: 10px;")
            self.route_layout.insertWidget(self.route_layout.count() - 1, result)

    def closeEvent(self, event):
        self.timer.stop()
        if self.worker is not None and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(3000)
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)   # стиль на всё приложение — диалоги тоже тёмные
    window = RouteMonitorWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()