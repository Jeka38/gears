# Импорт модуля для работы с операционной системой (пути, файлы, окружение)
import os

# Импорт модуля для получения версии Python
import platform

# Импорт модуля для ведения логов (журналирования событий)
import logging

# Импорт модуля для асинхронного программирования
import asyncio

# Импорт модуля для вычисления хешей (здесь используется md5 и sha1)
import hashlib

# Импорт модуля для работы с форматом JSON
import json

# Импорт модуля для поиска файлов по шаблонам (wildcards)
import fnmatch

# Импорт модуля для работы с SQLite
import sqlite3

# Импорт модуля для работы с правами доступа и типами файлов
import stat

# Импорт модуля для рекурсивного удаления директорий
import shutil

# Импорт модуля для работы с датой и временем
import datetime

# Импорт модуля для корректной работы с URL (в частности quote для имён файлов)
import urllib.parse

# Импорт функции для загрузки переменных окружения из .env файла
from dotenv import load_dotenv

# Импорт основного класса XMPP-клиента из библиотеки slixmpp
from slixmpp import ClientXMPP

# Импорт вспомогательных классов для работы с XML и обработчиками
from slixmpp.xmlstream import ET, handler, matcher

# Загружаем переменные из файла .env в os.environ
load_dotenv()

# Настраиваем базовое логирование: уровень INFO и простой формат
logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')

# Лимит квоты в гигабайтах (берём из переменной окружения или 15 по умолчанию)
QUOTA_LIMIT_GB = int(os.getenv('QUOTA_GB', 15))

# Переводим лимит в байты (1 ГБ = 1024³ байт)
QUOTA_LIMIT_BYTES = QUOTA_LIMIT_GB * 1024 * 1024 * 1024

# JID администратора
ADMIN_JID = os.getenv('ADMIN_JID')

# Путь к файлу белого списка
WHITELIST_FILE = os.getenv('WHITELIST_FILE', 'whitelist.json')

# Путь к базе данных
DB_PATH = os.getenv('DB_PATH', '/app/data/bot.db')

# Лимит вложенности директорий (не более N уровней)
MAX_DIR_DEPTH = int(os.getenv('MAX_DIR_DEPTH', 2))

# Версия софта
VERSION = os.getenv('APP_VERSION', '1.1')


class Database:
    def __init__(self, db_path):
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


# Основной класс бота — наследуется от ClientXMPP
class OBBFastBot(ClientXMPP):

    # Конструктор класса
    def __init__(self, jid, password, dest_dir, base_url):
        # Вызываем конструктор родительского класса (передаём JID и пароль)
        super().__init__(jid, password)

        # Папка, куда будем сохранять полученные файлы
        self.dest_dir = dest_dir

        # Базовый URL для скачивания файлов (без завершающего слеша)
        self.base_url = (base_url or "").rstrip('/')

        # Словарь для хранения информации о файлах, которые сейчас передаются
        self.pending_files = {}
        asyncio.create_task(self.cleanup_pending_files())

        # Инициализация базы данных
        self.db = Database(DB_PATH)
        self.migrate_json_to_db()

        # Миграция имен файлов (замена пробелов на подчёркивания)
        self.migrate_filenames()

        # Регистрируем плагин XEP-0030 (Service Discovery)
        self.register_plugin('xep_0030')
        # Регистрируем плагин XEP-0199 (XMPP Ping)
        self.register_plugin('xep_0199')
        # Включаем автоматический пинг сервера (Keepalive) каждые 60 секунд
        self['xep_0199'].send_keepalive = True
        self['xep_0199'].interval = 60
        # Регистрируем плагин XEP-0092 (Software Version)
        self.register_plugin('xep_0092')
        self['xep_0092'].software_name = os.getenv('APP_NAME', 'OBBFastBot')
        # Версия в стиле: OBBFastBot 1.1 on Python 3.12.12 + slixmpp
        import slixmpp
        self['xep_0092'].version = f"{VERSION} on Python {platform.python_version()} + slixmpp {slixmpp.__version__}"

        # Подписываемся на событие успешного входа в сеть
        self.add_event_handler("session_start", self.start)

        # Подписываемся на входящие сообщения (chat / normal)
        self.add_event_handler("message", self.handle_message)

        # Обработка подписки на присутствие
        self.add_event_handler("presence_subscribe", self.handle_presence_subscribe)
        self.add_event_handler("presence_subscribed", self.handle_presence_subscribed)
        self.add_event_handler("presence_unsubscribe", self.handle_presence_unsubscribe)
        self.add_event_handler("presence_unsubscribed", self.handle_presence_unsubscribed)

        # Обработчики для логирования XML
        self.add_event_handler("xml_in", self.log_xml_in)
        self.add_event_handler("xml_out", self.log_xml_out)

        # Регистрируем обработчик входящих SI (Stream Initiation) запросов
        self.register_handler(handler.Callback('SI',
            matcher.MatchXPath('{jabber:client}iq/{http://jabber.org/protocol/si}si'),
            self.handle_raw_si))

        # Регистрируем обработчик входящих S5B (SOCKS5 Bytestreams) запросов
        self.register_handler(handler.Callback('S5B',
            matcher.MatchXPath('{jabber:client}iq/{http://jabber.org/protocol/bytestreams}query'),
            self.handle_raw_s5b))

        # Явный обработчик для XEP-0199 Ping (некоторые клиенты ждут элемент в ответе)
        self.register_handler(handler.Callback('Ping',
            matcher.MatchXPath('{jabber:client}iq/{urn:xmpp:ping}ping'),
            self.handle_ping))

    # Асинхронный цикл очистки зависших передач
    async def cleanup_pending_files(self):
        while True:
            try:
                await asyncio.sleep(60)
                now = asyncio.get_event_loop().time()
                to_delete = [sid for sid, info in self.pending_files.items()
                             if now - info.get('timestamp', now) > 600]
                for sid in to_delete:
                    logging.info(f"CLEANUP: Expiring pending file sid={sid}")
                    del self.pending_files[sid]
            except Exception as e:
                logging.error(f"CLEANUP ERROR: {e}")

    # Асинхронный обработчик события успешного входа в аккаунт
    async def start(self, event):
        # Сообщаем серверу, что мы поддерживаем SI (Stream Initiation)
        self['xep_0030'].add_feature('http://jabber.org/protocol/si')

        # Сообщаем, что поддерживаем SOCKS5 Bytestreams
        self['xep_0030'].add_feature('http://jabber.org/protocol/bytestreams')

        # Указываем, что поддерживаем профиль передачи файлов через SI
        self['xep_0030'].add_feature('http://jabber.org/protocol/si/profile/file-transfer')

        # Отправляем присутствие (online) со статус-сообщением
        status = os.getenv('STATUS_MESSAGE', 'Для помощи по боту напиши ? или help')
        self.send_presence(pstatus=status)

        # Запрашиваем ростер (список контактов)
        await self.get_roster()

        # Пишем в лог, что бот успешно запустился
        logging.info(f"✅ БОТ ЗАПУЩЕН: {self.boundjid}")

    def migrate_json_to_db(self):
        try:
            if os.path.exists(WHITELIST_FILE):
                if os.path.isfile(WHITELIST_FILE):
                    with open(WHITELIST_FILE, 'r') as f:
                        data = json.load(f)
                        for entry in data:
                            self.db.add_to_whitelist(entry)
                    logging.info(f"MIGRATED {len(data)} entries from {WHITELIST_FILE} to database")
                    os.remove(WHITELIST_FILE)
                elif os.path.isdir(WHITELIST_FILE):
                    logging.warning(f"{WHITELIST_FILE} is a directory, removing it")
                    os.rmdir(WHITELIST_FILE)
        except Exception as e:
            logging.error(f"MIGRATION ERROR: {e}")

    # Логирование входящего XML
    def log_xml_in(self, xml):
        logging.info(f"RECV: {xml}")

    # Логирование исходящего XML
    def log_xml_out(self, xml):
        logging.info(f"SEND: {xml}")

    # Проверяем, разрешён ли доступ данному JID
    def is_allowed(self, jid):
        bare_jid = jid.bare.lower()
        if ADMIN_JID and bare_jid == ADMIN_JID.lower():
            return True

        # Проверка чёрного списка
        blacklist = self.db.get_blacklist()
        if bare_jid in blacklist or jid.domain.lower() in blacklist:
            return False

        whitelist = self.db.get_whitelist()
        if '*' in whitelist:
            return True

        domain = jid.domain.lower()
        return bare_jid in whitelist or domain in whitelist

    # Рекурсивная замена пробелов на подчёркивания в именах файлов
    def migrate_filenames(self):
        logging.info("START: Filename migration (spaces to underscores)")
        count = 0
        for root, dirs, files in os.walk(self.dest_dir):
            for f in files:
                if ' ' in f:
                    old_path = os.path.join(root, f)
                    new_path = os.path.join(root, f.replace(' ', '_'))
                    try:
                        os.rename(old_path, new_path)
                        count += 1
                    except Exception as e:
                        logging.error(f"MIGRATE ERROR for {old_path}: {e}")
        if count > 0:
            logging.info(f"FINISH: Renamed {count} files during migration")

    # Красивое кодирование URL (сохраняем кириллицу для читаемости)
    def safe_quote(self, text):
        # Заменяем пробелы на подчёркивания
        text = text.replace(' ', '_')
        return "".join(c if ord(c) >= 128 or c.isalnum() or c in '._-~/:?=&()'
                       else urllib.parse.quote(c) for c in text)

    def send_message(self, mto, mbody, msubject=None, mtype=None, mhtml=None,
                     mfrom=None, mnick=None):
        super().send_message(mto, mbody, msubject, mtype, mhtml, mfrom, mnick)

    # Получаем уникальный путь для предотвращения перезаписи
    def get_unique_path(self, path):
        if not os.path.exists(path):
            return path

        base, ext = os.path.splitext(path)
        counter = 1
        while True:
            new_path = f"{base}_{counter}{ext}"
            if not os.path.exists(new_path):
                return new_path
            counter += 1

    # Получаем (и при необходимости создаём) персональную папку пользователя
    def get_user_info(self, jid):
        bare_jid = jid.bare.lower()
        user_hash = self.db.get_user_folder(bare_jid)

        is_new = False
        if not user_hash:
            # Если папки ещё нет в БД, создаём новый хеш
            user_hash = hashlib.md5(bare_jid.encode()).hexdigest()
            self.db.set_user_folder(bare_jid, user_hash)
            is_new = True

        # Формируем путь к папке пользователя
        user_dir = os.path.join(self.dest_dir, user_hash)

        # Создаём папку, если её ещё нет
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
            is_new = True

        if is_new:
            # Уведомляем администратора о новом пользователе
            notify_level = os.getenv('ADMIN_NOTIFY_LEVEL', 'all').lower()
            if ADMIN_JID and notify_level in ('all', 'registrations'):
                self.send_message(mto=ADMIN_JID, mbody=f"🆕 Новый пользователь: {bare_jid} ({user_hash})", mtype='chat')

        # Возвращаем путь к папке и хеш
        return user_dir, user_hash

    # Подсчитываем суммарный размер всех файлов в папке (рекурсивно)
    def get_dir_size(self, path):
        # Суммируем размер каждого файла во всех вложенных папках
        return sum(os.path.getsize(os.path.join(d, f))
                   for d, _, fs in os.walk(path) for f in fs)

    # Форматируем размер в человеко-читаемый вид (Б → кБ → МБ → ГБ)
    def format_size(self, size):
        for unit in ['Б', 'кБ', 'МБ', 'ГБ']:
            if size < 1024:
                res = f"{size:.1f}".replace('.', ',')
                return f"{res} {unit}"
            size /= 1024
        return f"{size:.1f} ГБ".replace('.', ',')

    # Получаем все элементы рекурсивно с ограничением вложенности
    def get_all_items(self, user_dir):
        items = []
        for root, dirs, files in os.walk(user_dir):
            rel_root = os.path.relpath(root, user_dir)
            if rel_root == ".":
                rel_root = ""

            # Ограничение вложенности: не более MAX_DIR_DEPTH уровней директорий
            if rel_root != "" and rel_root.count(os.sep) >= MAX_DIR_DEPTH:
                continue

            for d in dirs:
                path = os.path.join(rel_root, d)
                if path.count(os.sep) < MAX_DIR_DEPTH:
                    items.append(path + "/")
            for f in files:
                path = os.path.join(rel_root, f)
                # Файлы могут находиться в директориях уровня MAX_DIR_DEPTH
                if path.count(os.sep) <= MAX_DIR_DEPTH:
                    items.append(path)
        return sorted(items)

    # Безопасное получение пути внутри папки пользователя
    def get_safe_path(self, user_dir, path_str):
        user_dir = os.path.abspath(user_dir)
        target_path = os.path.abspath(os.path.join(user_dir, path_str.strip().lstrip('/')))
        if not target_path.startswith(user_dir):
            return None
        return target_path

    # Разрешение аргумента как индекса или пути
    def resolve_item(self, user_dir, arg, items):
        try:
            idx = int(arg) - 1
            if 0 <= idx < len(items):
                return self.get_safe_path(user_dir, items[idx])
        except ValueError:
            pass
        return self.get_safe_path(user_dir, arg)

    # Разрешение списка аргументов (индексы, пути, шаблоны)
    def resolve_items_list(self, user_dir, arg, items):
        resolved = []
        parts = [p.strip() for p in arg.split(',') if p.strip()]
        for p in parts:
            if '*' in p or '?' in p:
                if '/' not in p:
                    for itm in items:
                        name = os.path.basename(itm.rstrip('/'))
                        if fnmatch.fnmatch(name, p):
                            path = self.get_safe_path(user_dir, itm)
                            if path: resolved.append(path)
                else:
                    matches = fnmatch.filter(items, p)
                    for m in matches:
                        path = self.get_safe_path(user_dir, m)
                        if path: resolved.append(path)
            else:
                path = self.resolve_item(user_dir, p, items)
                if path: resolved.append(path)
        return list(dict.fromkeys(resolved))

    def get_help_text(self, is_admin=False, user_hash=None):
        text = (
            "команды:\n"
            "ls - список файлов и каталогов в папке пользователя.\n"
            "ls <-s|-l>, lss, lsl - список файлов (-s: размер, -l: подробно). Пример: ls -l\n"
            "mkdir <путь> - создать директорию.\n"
            "rmdir <номер|путь> - удалить пустую директорию.\n"
            "mv <номер|путь> <номер|путь> - переместить/переименовать.\n"
            "rm <номер>[,<номер>],.. - удаление файлов по номеру или rm * - для удаления всех файлов.\n"
            "link <номер>[,<номер>],.. - получение ссылок на файлы или lnk * - для всех файлов.\n"
            "priv - сделать архив приватным (создать index.html).\n"
            "pub - сделать архив публичным (удалить index.html).\n"
            "ping - проверить доступность бота.\n"
            "help или ? - список команд."
        )
        if user_hash:
            text += f"\n\n📂 Ваш архив: {self.base_url}/{user_hash}/"
            text += "\nЧтобы запретить просмотр списка файлов через браузер, используйте команду priv."

        if is_admin:
            text += (
                "\n\n🔧 Админ-команды:\n"
                "add <jid|domain|*> - разрешить доступ.\n"
                "del <jid|domain|*> - запретить доступ.\n"
                "block <jid|domain> - в чёрный список.\n"
                "unblock <jid|domain> - убрать из чёрного списка.\n"
                "list - показать белый и чёрный списки."
            )
        return text

    # Обработчик запроса на подписку
    def handle_presence_subscribe(self, presence):
        jid = presence['from'].bare
        logging.info(f"🆕 Запрос подписки от {jid}")
        notify_level = os.getenv('ADMIN_NOTIFY_LEVEL', 'all').lower()
        if ADMIN_JID and notify_level == 'all':
            self.send_message(mto=ADMIN_JID, mbody=f"➕ Пользователь {jid} отправил запрос на подписку", mtype='chat')
        self.send_presence(pto=jid, ptype='subscribed')
        self.send_presence(pto=jid, ptype='subscribe')
        is_admin = ADMIN_JID and jid == ADMIN_JID.lower()
        _, user_hash = self.get_user_info(presence['from'])
        welcome_msg = f"Добро пожаловать!\nЯ бот для быстрой передачи файлов.\n\n{self.get_help_text(is_admin, user_hash)}"
        self.send_message(mto=jid, mbody=welcome_msg, mtype='chat')

    def handle_presence_subscribed(self, presence):
        jid = presence['from'].bare
        logging.info(f"✅ Подписка подтверждена от {jid}")

    def handle_presence_unsubscribe(self, presence):
        jid = presence['from'].bare
        logging.info(f"➖ Запрос отписки от {jid}")

    def handle_presence_unsubscribed(self, presence):
        jid = presence['from'].bare
        logging.info(f"❌ Подписка отменена от {jid}")

    # Обработчик обычных текстовых сообщений
    def handle_message(self, msg):
        if msg['type'] not in ('chat', 'normal') or not msg['body']:
            return

        if not self.is_allowed(msg['from']):
            logging.info(f"ACCESS DENIED (msg) from {msg['from']}")
            notify_level = os.getenv('ADMIN_NOTIFY_LEVEL', 'all').lower()
            if ADMIN_JID and notify_level == 'all':
                self.send_message(mto=ADMIN_JID, mbody=f"🚫 Попытка сообщения от {msg['from']}", mtype='chat')
            self.send_message(mto=msg['from'],
                              mbody=f"У вас нет прав для пользования ботом. Обратитесь к {ADMIN_JID}",
                              mtype='chat')
            return

        parts = msg['body'].strip().split()
        if not parts:
            return
        cmd = parts[0].lower()
        user_dir, user_hash = self.get_user_info(msg['from'])

        def reply(text):
            self.send_message(mto=msg['from'], mbody=text, mtype='chat')

        # Команды
        if cmd in ('help', '?'):
            if len(parts) != 1: return
            is_admin = ADMIN_JID and msg['from'].bare.lower() == ADMIN_JID.lower()
            used = self.get_dir_size(user_dir)
            help_text = self.get_help_text(is_admin, user_hash) + f"\n\n📊 Квота: {self.format_size(used)} / {self.format_size(QUOTA_LIMIT_BYTES)}"
            reply(help_text)

        elif cmd == 'ping':
            if len(parts) != 1: return
            reply("pong")

        elif cmd == 'mkdir':
            if len(parts) != 2: return
            target = self.get_safe_path(user_dir, parts[1])
            if target:
                rel = os.path.relpath(target, user_dir)
                if rel != "." and rel.count(os.sep) >= MAX_DIR_DEPTH:
                    return reply(f"❌ Ошибка: Максимальная глубина вложенности — {MAX_DIR_DEPTH} уровня")
                try:
                    os.makedirs(target, exist_ok=True)
                    reply(f"📁 Директория создана: {rel}")
                except Exception as e:
                    reply(f"❌ Ошибка: {e}")
            else:
                reply("❌ Недопустимый путь")

        elif cmd == 'rmdir':
            if len(parts) != 2: return
            items = self.get_all_items(user_dir)
            resolved_paths = self.resolve_items_list(user_dir, parts[1], items)
            removed_count = 0
            for target in resolved_paths:
                if target and os.path.isdir(target):
                    try:
                        os.rmdir(target)
                        removed_count += 1
                    except Exception:
                        pass
            if removed_count:
                reply(f"🗑 Удалено директорий: {removed_count}")
            else:
                reply("❌ Директории не найдены или не пусты")

        elif cmd == 'mv':
            if len(parts) != 3: return
            items = self.get_all_items(user_dir)
            dst = self.resolve_item(user_dir, parts[2], items)
            if not dst:
                return reply("❌ Недопустимый путь назначения")

            resolved_srcs = self.resolve_items_list(user_dir, parts[1], items)
            if not resolved_srcs:
                return reply("❌ Объекты для перемещения не найдены")

            if len(resolved_srcs) > 1:
                if not os.path.isdir(dst):
                    return reply("❌ При перемещении нескольких объектов назначение должно быть директорией")

                moved_count = 0
                for src in resolved_srcs:
                    if os.path.abspath(src) == os.path.abspath(dst):
                        continue

                    new_dst = os.path.join(dst, os.path.basename(src.rstrip('/')))
                    rel_dst = os.path.relpath(new_dst, user_dir)

                    is_dir = os.path.isdir(src)
                    limit = MAX_DIR_DEPTH if not is_dir else MAX_DIR_DEPTH - 1
                    if rel_dst != "." and rel_dst.count(os.sep) > limit:
                         continue

                    try:
                        new_dst = self.get_unique_path(new_dst)
                        os.rename(src, new_dst)
                        moved_count += 1
                    except Exception:
                        pass
                reply(f"🚚 Перемещено объектов: {moved_count}")
            else:
                src = resolved_srcs[0]
                if src and os.path.exists(src):
                    try:
                        # Если цель - директория, помещаем внутрь
                        final_dst = dst
                        if os.path.isdir(dst):
                             final_dst = os.path.join(dst, os.path.basename(src.rstrip('/')))

                        rel_dst = os.path.relpath(final_dst, user_dir)
                        is_dir = os.path.isdir(src)
                        limit = MAX_DIR_DEPTH if not is_dir else MAX_DIR_DEPTH - 1
                        if rel_dst != "." and rel_dst.count(os.sep) > limit:
                             return reply(f"❌ Ошибка: Превышена максимальная глубина вложенности")

                        final_dst = self.get_unique_path(final_dst)
                        os.rename(src, final_dst)
                        reply(f"🚚 Перемещено: {os.path.relpath(src, user_dir)} -> {os.path.relpath(final_dst, user_dir)}")
                    except Exception as e:
                        reply(f"❌ Ошибка: {e}")
                else:
                    reply("❌ Файл не найден")

        elif cmd in ('ls', 'lss', 'lsl'):
            if len(parts) > 2: return
            items = self.get_all_items(user_dir)
            if not items:
                return reply("📁 Папка пуста")

            mode = 'links'
            if cmd == 'lss': mode = 'size'
            elif cmd == 'lsl': mode = 'long'
            elif len(parts) == 2:
                if parts[1] == '-s': mode = 'size'
                elif parts[1] == '-l': mode = 'long'
                else: return

            res = []
            for i, itm in enumerate(items):
                depth = itm.count('/')
                if itm.endswith('/'): depth -= 1

                name = os.path.basename(itm.rstrip('/'))
                if itm.endswith('/'): name += "/"

                if depth > 0:
                    display_itm = "    " * depth + "└── " + name
                else:
                    display_itm = name

                full_path = os.path.join(user_dir, itm)

                if mode == 'links':
                    res.append(f"{i+1} - {display_itm}")
                elif mode == 'size':
                    if itm.endswith('/'):
                        res.append(f"{i+1} - {display_itm} [директория]")
                    else:
                        size = self.format_size(os.path.getsize(full_path))
                        res.append(f"{i+1} - {display_itm} [{size}]")
                elif mode == 'long':
                    st = os.stat(full_path)
                    size = self.format_size(st.st_size)
                    mtime = datetime.datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M')
                    if itm.endswith('/'):
                        res.append(f"{i+1} - {display_itm} (директория, {mtime})")
                    else:
                        res.append(f"{i+1} - {display_itm} ({size}, загружен {mtime})")
            reply("\n" + "\n".join(res))

        elif cmd in ('link', 'lnk'):
            if len(parts) != 2: return
            items = self.get_all_items(user_dir)
            if not items:
                return reply("📁 Папка пуста")

            if parts[1] == '*':
                res = []
                for i, itm in enumerate(items):
                    if not itm.endswith('/'):
                        res.append(f"{i+1} - {self.base_url}/{user_hash}/{self.safe_quote(itm)}")
                reply("\n".join(res))
            else:
                resolved_paths = self.resolve_items_list(user_dir, parts[1], items)
                res = []
                for path in resolved_paths:
                    if not os.path.isdir(path):
                        rel = os.path.relpath(path, user_dir)
                        try: idx = items.index(rel if not os.path.isdir(path) else rel + "/")
                        except ValueError: idx = -1
                        res.append(f"{idx+1 if idx >=0 else '?'} - {self.base_url}/{user_hash}/{self.safe_quote(rel)}")
                if res: reply("\n".join(res))

        elif cmd == 'rm':
            if not (2 <= len(parts) <= 3): return
            items = self.get_all_items(user_dir)
            if not items:
                return reply("📁 Папка пуста")

            if parts[1] == '*':
                if len(parts) == 3 and parts[2].lower() == 'confirm':
                    top_items = os.listdir(user_dir)
                    for item in top_items:
                        item_path = os.path.join(user_dir, item)
                        try:
                            if os.path.isdir(item_path): shutil.rmtree(item_path)
                            else: os.remove(item_path)
                        except Exception: pass
                    reply("🗑 Все файлы и папки удалены.")
                else:
                    reply("⚠ Чтобы удалить ВСЕ файлы, напишите: rm * confirm")
            else:
                if len(parts) != 2: return
                resolved_paths = self.resolve_items_list(user_dir, parts[1], items)
                removed_count = 0
                for path in resolved_paths:
                    try:
                        if os.path.isdir(path): shutil.rmtree(path)
                        else: os.remove(path)
                        removed_count += 1
                    except Exception: pass
                if removed_count: reply(f"🗑 Удалено объектов: {removed_count}")

        elif cmd == 'priv':
            index_path = os.path.join(user_dir, 'index.html')
            if not os.path.exists(index_path):
                with open(index_path, 'w') as f:
                    f.write("<html><body><h1>Private Archive</h1></body></html>")
                reply("🔒 Архив теперь приватный (создан index.html)")
            else: reply("ℹ Архив уже приватный.")

        elif cmd == 'pub':
            index_path = os.path.join(user_dir, 'index.html')
            if os.path.exists(index_path):
                os.remove(index_path)
                reply("🔓 Архив теперь публичный (удалён index.html)")
            else: reply("ℹ Архив уже публичный.")

        # Админ-команды
        if ADMIN_JID and msg['from'].bare.lower() == ADMIN_JID.lower():
            if cmd == 'add' and len(parts) == 2:
                entries = [e.strip().lower() for e in parts[1].split(',') if e.strip()]
                added = []
                for entry in entries:
                    if entry == '*' or '@' in entry or '.' in entry:
                        self.db.add_to_whitelist(entry)
                        added.append(entry)
                if added:
                    if '*' in added: reply("🌟 Доступ разрешён для ВСЕХ пользователей.")
                    else: reply(f"➕ Добавлено в белый список: {', '.join(added)}")
                else: reply("⚠ Неверный формат. Используйте user@domain, domain или *")

            elif cmd == 'del' and len(parts) == 2:
                entries = [e.strip().lower() for e in parts[1].split(',') if e.strip()]
                whitelist = self.db.get_whitelist()
                removed = []
                for entry in entries:
                    if entry in whitelist:
                        self.db.remove_from_whitelist(entry)
                        removed.append(entry)
                if removed: reply(f"➖ Удалено из белого списка: {', '.join(removed)}")
                else: reply("❓ Ничего не найдено для удаления из белого списка.")

            elif cmd == 'block' and len(parts) == 2:
                entries = [e.strip().lower() for e in parts[1].split(',') if e.strip()]
                added = []
                for entry in entries:
                    if '@' in entry or '.' in entry:
                        self.db.add_to_blacklist(entry)
                        added.append(entry)
                if added: reply(f"🚫 Добавлено в чёрный список: {', '.join(added)}")
                else: reply("⚠ Неверный формат. Используйте user@domain или domain")

            elif cmd == 'unblock' and len(parts) == 2:
                entries = [e.strip().lower() for e in parts[1].split(',') if e.strip()]
                blacklist = self.db.get_blacklist()
                removed = []
                for entry in entries:
                    if entry in blacklist:
                        self.db.remove_from_blacklist(entry)
                        removed.append(entry)
                if removed: reply(f"✅ Удалено из чёрного списка: {', '.join(removed)}")
                else: reply("❓ Ничего не найдено для удаления из чёрного списка.")

            elif cmd == 'list' and len(parts) == 1:
                whitelist = self.db.get_whitelist()
                blacklist = self.db.get_blacklist()
                res_w = "\n".join(sorted(whitelist))
                res_b = "\n".join(sorted(blacklist))
                reply(f"📄 Белый список:\n{res_w or '(пусто)'}\n\n🚫 Чёрный список:\n{res_b or '(пусто)'}")

    # SI handler
    def handle_raw_si(self, iq):
        if not self.is_allowed(iq['from']):
            logging.info(f"ACCESS DENIED (SI) from {iq['from']}")
            notify_level = os.getenv('ADMIN_NOTIFY_LEVEL', 'all').lower()
            if ADMIN_JID and notify_level == 'all':
                self.send_message(mto=ADMIN_JID, mbody=f"🚫 Попытка передачи файла от {iq['from']}", mtype='chat')
            self.send_message(mto=iq['from'], mbody=f"У вас нет прав для пользования ботом. Обратитесь к {ADMIN_JID}", mtype='chat')
            reply = iq.reply(); reply['type'] = 'error'; return reply.send()

        try:
            si = iq.xml.find('{http://jabber.org/protocol/si}si')
            sid, tag = si.get('id'), si.find('{http://jabber.org/protocol/si/profile/file-transfer}file')
            fname = os.path.basename(tag.get('name')).replace(' ', '_')
            fsize = int(tag.get('size', 0))
            logging.info(f"SI REQUEST: {fname} ({fsize} bytes) from {iq['from']}, sid={sid}")
            user_dir, _ = self.get_user_info(iq['from'])
            if self.get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                logging.info(f"QUOTA EXCEEDED for {iq['from']}")
                self.send_message(mto=iq['from'], mbody="⚠ Квота превышена!", mtype='chat')
                reply = iq.reply(); reply['type'] = 'error'; return reply.send()

            self.pending_files[sid] = {'name': fname, 'size': fsize, 'timestamp': asyncio.get_event_loop().time()}
            reply = iq.reply()
            res_si = ET.Element('{http://jabber.org/protocol/si}si', {'id': sid})
            feature = ET.SubElement(res_si, '{http://jabber.org/protocol/feature-neg}feature')
            x = ET.SubElement(feature, '{jabber:x:data}x', type='submit')
            field = ET.SubElement(x, '{jabber:x:data}field', var='stream-method')
            ET.SubElement(field, '{jabber:x:data}value').text = 'http://jabber.org/protocol/bytestreams'
            reply.append(res_si); reply.send()
        except Exception as e: logging.error(f"SI ERROR: {e}")

    def handle_raw_s5b(self, iq):
        logging.info(f"S5B REQUEST from {iq['from']}")
        asyncio.create_task(self._manual_socks5_connect(iq))

    def handle_ping(self, iq):
        logging.info(f"PING RECV from {iq['from']}")
        reply = iq.reply()
        ping = ET.Element('{urn:xmpp:ping}ping')
        reply.append(ping); reply.send()
        logging.info(f"PONG SENT to {iq['from']}")

    async def _manual_socks5_connect(self, iq):
        sid = None
        try:
            query = iq.xml.find('{http://jabber.org/protocol/bytestreams}query')
            if query is None: return
            sid = query.get('sid')
            file_info = self.pending_files.get(sid)
            if not file_info: return
            dst_addr = hashlib.sha1(f"{sid}{iq['from'].full}{self.boundjid.full}".encode()).hexdigest()
            hosts = query.findall('{http://jabber.org/protocol/bytestreams}streamhost')
            for host in hosts:
                h_host, h_port, h_jid = host.get('host'), int(host.get('port', 1080)), host.get('jid')
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(h_host, h_port), 5)
                    writer.write(b"\x05\x01\x00"); await writer.drain()
                    if await reader.read(2) != b"\x05\x00": writer.close(); continue
                    writer.write(b"\x05\x01\x00\x03" + bytes([len(dst_addr)]) + dst_addr.encode() + b"\x00\x00"); await writer.drain()
                    resp = await reader.read(4)
                    if not resp or resp[1] != 0x00: writer.close(); continue
                    atyp = resp[3]
                    if atyp == 0x01: await reader.read(6)
                    elif atyp == 0x03: addr_len = await reader.read(1); await reader.read(addr_len[0] + 2)
                    elif atyp == 0x04: await reader.read(18)
                    reply = iq.reply()
                    res_q = ET.Element('{http://jabber.org/protocol/bytestreams}query', {'sid': sid})
                    ET.SubElement(res_q, 'streamhost-used', jid=h_jid)
                    reply.append(res_q); reply.send()
                    await self.download_file_task(reader, file_info, iq['from'])
                    writer.close(); await writer.wait_closed(); return
                except Exception: continue
            reply = iq.reply(); reply['type'] = 'error'; reply.send()
        except Exception as e: logging.error(f"SOCKS5 ERROR: {e}")
        finally:
            if sid in self.pending_files: del self.pending_files[sid]

    async def download_file_task(self, reader, file_info, peer_jid):
        user_dir, user_hash = self.get_user_info(peer_jid)
        fname = os.path.basename(file_info['name'])
        path = os.path.join(user_dir, fname)
        received = 0
        try:
            with open(path, 'wb') as f:
                while received < file_info['size']:
                    chunk = await reader.read(min(file_info['size'] - received, 1048576))
                    if not chunk: break
                    f.write(chunk); received += len(chunk)
                f.flush(); os.fsync(f.fileno())
            if received == file_info['size']:
                safe_name = self.safe_quote(file_info['name'])
                self.send_message(mto=peer_jid, mbody=f"✅ Готово!\n{self.base_url}/{user_hash}/{safe_name}", mtype='chat')
            else:
                if os.path.exists(path): os.remove(path)
        except Exception as e:
            logging.error(f"Ошибка при приёме файла: {e}")
            if os.path.exists(path): os.remove(path)


# Точка входа — основная асинхронная функция
async def main():
    # Формируем JID с ресурсом, если он указан
    jid = os.getenv('XMPP_JID')
    resource = os.getenv('XMPP_RESOURCE')
    if resource:
        jid = f"{jid}/{resource}"

    # Создаём экземпляр бота, передавая параметры из переменных окружения
    bot = OBBFastBot(
        jid,
        os.getenv('XMPP_PASSWORD'),
        os.getenv('DOWNLOAD_DIR'),
        os.getenv('BASE_URL')
    )

    # Явно указываем механизм SASL (некоторые серверы требуют именно его)
    bot.sasl_mechanism = 'SCRAM-SHA-1'

    # Отключаем проблемные / устаревшие механизмы
    bot.disabled_sasl_mechanisms = {'DIGEST-MD5', 'SCRAM-SHA-1-PLUS'}

    # Запускаем соединение с указанным сервером и портом
    xmpp_host = os.getenv('XMPP_HOST', 'jabberworld.info')
    xmpp_port = int(os.getenv('XMPP_PORT', 5222))
    bot.connect((xmpp_host, xmpp_port))

    # Ждём отключения (работаем до разрыва соединения)
    await bot.disconnected


# Запуск программы
if __name__ == '__main__':
    # Запускаем асинхронный цикл событий
    asyncio.run(main())
