import os
import sqlite3
import logging
from config import DB_PATH

class Database:
    def __init__(self, db_path=DB_PATH):
        # Преобразуем в абсолютный путь для надёжности
        self.db_path = os.path.abspath(db_path)
        logging.info(f"Инициализация базы данных: {self.db_path}")

        # Проверка, не является ли путь директорией (ошибка Docker volume)
        if os.path.isdir(self.db_path):
            # Если это директория, попробуем использовать файл внутри неё
            logging.warning(f"ВНИМАНИЕ: Путь {self.db_path} — директория. Используем {self.db_path}/bot_data.db")
            self.db_path = os.path.join(self.db_path, "bot_data.db")

        # Убеждаемся, что папка для базы данных существует
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            logging.info(f"Создание директории для БД: {db_dir}")
            os.makedirs(db_dir, exist_ok=True)

        self._create_tables()

    def _create_tables(self):
        logging.info(f"Подключение к SQLite: {self.db_path}")
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS whitelist (
                        entry TEXT PRIMARY KEY
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS blacklist (
                        entry TEXT PRIMARY KEY
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS user_folders (
                        jid TEXT PRIMARY KEY,
                        folder_hash TEXT NOT NULL
                    )
                """)
        finally:
            conn.close()

    def add_to_whitelist(self, entry):
        entry = entry.lower()
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("INSERT OR IGNORE INTO whitelist (entry) VALUES (?)", (entry,))
        finally:
            conn.close()

    def remove_from_whitelist(self, entry):
        entry = entry.lower()
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM whitelist WHERE entry = ?", (entry,))
        finally:
            conn.close()

    def get_whitelist(self):
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT entry FROM whitelist")
            return {row[0] for row in cursor.fetchall()}
        finally:
            conn.close()

    def add_to_blacklist(self, entry):
        entry = entry.lower()
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("INSERT OR IGNORE INTO blacklist (entry) VALUES (?)", (entry,))
        finally:
            conn.close()

    def remove_from_blacklist(self, entry):
        entry = entry.lower()
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM blacklist WHERE entry = ?", (entry,))
        finally:
            conn.close()

    def get_blacklist(self):
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT entry FROM blacklist")
            return {row[0] for row in cursor.fetchall()}
        finally:
            conn.close()

    def get_user_folder(self, jid):
        jid = jid.lower()
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT folder_hash FROM user_folders WHERE jid = ?", (jid,))
            row = cursor.fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def set_user_folder(self, jid, folder_hash):
        jid = jid.lower()
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("INSERT OR REPLACE INTO user_folders (jid, folder_hash) VALUES (?, ?)", (jid, folder_hash))
        finally:
            conn.close()
