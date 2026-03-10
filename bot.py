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

# Импорт модуля для корректной работы с URL (в частности quote для имён файлов)
import urllib.parse


# Импорт функции для загрузки переменных окружения из .env файла
from dotenv import load_dotenv

# Импорт библиотеки slixmpp
import slixmpp
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

# Версия софта
VERSION = os.getenv('APP_VERSION', '1.1')


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

        # Белый список
        self.whitelist = set()
        self.load_whitelist()

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
        self['xep_0092'].version = f"{VERSION} on Python {platform.python_version()} + slixmpp {slixmpp.__version__}"

        # Регистрируем плагины для передачи файлов
        self.register_plugin('xep_0066') # OOB
        self.register_plugin('xep_0234') # Jingle File Transfer

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

        # Явный обработчик для XEP-0199 Ping (некоторые клиенты ждут элемент в ответе)
        self.register_handler(handler.Callback('Ping',
            matcher.MatchXPath('{jabber:client}iq/{urn:xmpp:ping}ping'),
            self.handle_ping))


        # Явный обработчик для Jingle (XEP-0166)
        self.register_handler(handler.Callback('Jingle',
            matcher.MatchXPath('{jabber:client}iq/{urn:xmpp:jingle:1}jingle'),
            self.handle_jingle))

    # Обработчик Jingle (XEP-0166)
    def handle_jingle(self, iq):
        logging.info(f"JINGLE XML RECV: {iq}")
        jingle = iq.xml.find('{urn:xmpp:jingle:1}jingle')
        action = jingle.get('action')

        if action == 'session-initiate':
            asyncio.create_task(self.handle_jingle_initiate(iq, jingle))
        elif action == 'transport-info':
            # Обработка кандидатов SOCKS5 от отправителя (если нужно)
            pass
        elif action == 'session-terminate':
            sid = jingle.get('sid')
            if sid in self.pending_files:
                logging.info(f"Jingle session terminated: sid={sid}")
                del self.pending_files[sid]

    async def handle_jingle_initiate(self, iq, jingle):
        sid = jingle.get('sid')
        peer_jid = iq['from']

        # Проверка белого списка
        if not self.is_allowed(peer_jid):
            logging.info(f"ACCESS DENIED (Jingle) from {peer_jid}")
            self.send_message(mto=peer_jid, mbody="❌ Доступ запрещён. Вы не в белом списке.", mtype='chat')
            if ADMIN_JID:
                self.send_message(mto=ADMIN_JID, mbody=f"🚫 Попытка Jingle передачи от {peer_jid}", mtype='chat')
            reply = iq.reply()
            reply['type'] = 'error'
            reply['error']['condition'] = 'forbidden'
            return reply.send()

        try:
            content = jingle.find('{urn:xmpp:jingle:1}content')
            if content is None:
                logging.error(f"Jingle session-initiate missing <content/>: sid={sid}")
                return

            c_name = content.get('name')
            c_creator = content.get('creator', 'initiator')

            description = content.find('{urn:xmpp:jingle:apps:file-transfer:5}description')
            if description is None:
                 logging.error(f"Jingle session-initiate missing <description/>: sid={sid}")
                 return

            file_tag = description.find('{urn:xmpp:jingle:apps:file-transfer:5}file')
            if file_tag is None:
                 logging.error(f"Jingle session-initiate missing <file/>: sid={sid}")
                 return

            fname = file_tag.findtext('{urn:xmpp:jingle:apps:file-transfer:5}name')
            if not fname:
                fname = "jingle_file"
            fname = os.path.basename(fname).replace(' ', '_')

            fsize = int(file_tag.findtext('{urn:xmpp:jingle:apps:file-transfer:5}size') or 0)

            logging.info(f"JINGLE REQUEST: {fname} ({fsize} bytes) from {peer_jid}, sid={sid}, content_name={c_name}")

            user_dir, _ = self.get_user_info(peer_jid)
            if self.get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                logging.info(f"QUOTA EXCEEDED for {peer_jid}")
                self.send_message(mto=peer_jid, mbody="⚠ Квота превышена! Пожалуйста, удалите старые файлы.", mtype='chat')
                reply = iq.reply()
                reply['type'] = 'error'
                reply['error']['condition'] = 'not-acceptable'
                return reply.send()

            self.pending_files[sid] = {
                'name': fname,
                'size': fsize,
                'from': peer_jid.bare,
                'timestamp': asyncio.get_event_loop().time(),
                'jingle': True,
                'content_name': c_name,
                'content_creator': c_creator
            }

            # Используем только SOCKS5
            transport_s5b = content.find('{urn:xmpp:jingle:transports:s5b:1}transport')

            if transport_s5b is not None:
                await self.accept_jingle_s5b(iq, sid, transport_s5b)
            else:
                self.send_message(mto=peer_jid, mbody="⚠ Не найден подходящий транспорт для передачи файла (нужен SOCKS5).", mtype='chat')
                reply = iq.reply()
                reply['type'] = 'error'
                reply['error']['condition'] = 'feature-not-implemented'
                reply.send()

        except Exception as e:
            logging.error(f"JINGLE INITIATE ERROR: {e}")
            reply = iq.reply()
            reply['type'] = 'error'
            reply.send()

    def send_jingle_session_info(self, mto, sid, info):
        iq = self.make_iq_set()
        iq['to'] = mto
        jingle = ET.Element('{urn:xmpp:jingle:1}jingle', action='session-info', sid=sid, responder=self.boundjid.full)
        # Пустой session-info или с какой-то инфой
        iq.append(jingle)
        iq.send()
        logging.info(f"Jingle session-info SENT: sid={sid}")

    async def accept_jingle_s5b(self, iq, sid, transport):
        info = self.pending_files[sid]
        dst_sid = transport.get('sid', sid)

        # Переносим инфу
        if dst_sid != sid:
             self.pending_files[dst_sid] = self.pending_files[sid]

        hosts = []
        for candidate in transport.findall('{urn:xmpp:jingle:transports:s5b:1}candidate'):
            hosts.append({
                'host': candidate.get('host'),
                'port': int(candidate.get('port', 1080)),
                'jid': candidate.get('jid')
            })

        reply = iq.reply()
        jingle = ET.Element('{urn:xmpp:jingle:1}jingle', action='session-accept', sid=sid, responder=self.boundjid.full)
        content = ET.SubElement(jingle, '{urn:xmpp:jingle:1}content', creator=info['content_creator'], name=info['content_name'])
        ET.SubElement(content, '{urn:xmpp:jingle:apps:file-transfer:5}description')
        ET.SubElement(content, '{urn:xmpp:jingle:transports:s5b:1}transport', sid=dst_sid)
        reply.append(jingle)
        reply.send()
        logging.info(f"Jingle session accepted (S5B): sid={sid}, dst_sid={dst_sid}")

        # Шаг 3: После session-accept отправить session-info
        self.send_jingle_session_info(iq['from'], sid, info)

        # Запускаем коннект в фоне
        asyncio.create_task(self._socks5_connect_and_save(dst_sid, iq['from'], hosts, jingle_sid=sid))

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
        # Запускаем очистку зависших передач
        asyncio.create_task(self.cleanup_pending_files())

        # Миграция имен файлов (замена пробелов на подчёркивания)
        # Выполняем асинхронно, чтобы не блокировать старт сессии
        asyncio.create_task(asyncio.to_thread(self.migrate_filenames))

        # Поддержка OOB (XEP-0066) - только отправка (x:oob)
        self['xep_0030'].add_feature('jabber:x:oob')

        # Поддержка Jingle (XEP-0166) и Jingle File Transfer (XEP-0234)
        self['xep_0030'].add_feature('urn:xmpp:jingle:1')
        self['xep_0030'].add_feature('urn:xmpp:jingle:apps:file-transfer:5')
        self['xep_0030'].add_feature('urn:xmpp:jingle:transports:s5b:1')

        # Отправляем присутствие (online)
        self.send_presence()

        # Запрашиваем ростер (список контактов)
        await self.get_roster()

        # Пишем в лог, что бот успешно запустился
        logging.info(f"✅ БОТ ЗАПУЩЕН: {self.boundjid}")

    def load_whitelist(self):
        try:
            if os.path.exists(WHITELIST_FILE):

                if os.path.isdir(WHITELIST_FILE):
                    logging.warning(f"{WHITELIST_FILE} is directory, recreating file")
                    os.rmdir(WHITELIST_FILE)

                with open(WHITELIST_FILE, 'r') as f:
                    data = json.load(f)
                    self.whitelist = set(data)

            else:
                self.whitelist = set()
                with open(WHITELIST_FILE, 'w') as f:
                    json.dump([], f)

        except Exception as e:
            logging.error(f"LOAD WHITELIST ERROR: {e}")
            self.whitelist = set()

    # Сохраняем белый список в файл
    def save_whitelist(self):
        try:
            with open(WHITELIST_FILE, 'w') as f:
                json.dump(list(sorted(self.whitelist)), f, indent=4)
        except Exception as e:
            logging.error(f"SAVE WHITELIST ERROR: {e}")

    # Логирование входящего XML
    def log_xml_in(self, xml):
        logging.info(f"RECV: {xml}")

    # Логирование исходящего XML
    def log_xml_out(self, xml):
        logging.info(f"SEND: {xml}")

    # Проверяем, разрешён ли доступ данному JID
    def is_allowed(self, jid):
        bare_jid = jid.bare
        if ADMIN_JID and bare_jid == ADMIN_JID:
            return True
        # По умолчанию разрешаем сервер аккаунта бота
        if jid.domain == self.boundjid.domain:
            return True
        if '*' in self.whitelist:
            return True
        domain = jid.domain
        return bare_jid in self.whitelist or domain in self.whitelist

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
                     mfrom=None, mnick=None, oob_url=None):
        if mbody and not mbody.startswith('\n'):
            mbody = '\n' + mbody

        msg = self.make_message(mto, mbody, msubject, mtype, mhtml, mfrom, mnick)
        if oob_url:
            x_oob = ET.Element('{jabber:x:oob}x')
            url_el = ET.SubElement(x_oob, 'url')
            url_el.text = oob_url
            msg.append(x_oob)

        msg.send()

    # Получаем (и при необходимости создаём) персональную папку пользователя
    def get_user_info(self, jid):
        # Берём bare JID (без ресурса) и считаем от него md5
        user_hash = hashlib.md5(jid.bare.encode()).hexdigest()

        # Формируем путь к папке пользователя
        user_dir = os.path.join(self.dest_dir, user_hash)

        # Создаём папку, если её ещё нет
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
            # Уведомляем администратора о новом пользователе
            if ADMIN_JID:
                self.send_message(mto=ADMIN_JID, mbody=f"🆕 Новый пользователь: {jid.bare} ({user_hash})", mtype='chat')

        # Возвращаем путь к папке и хеш
        return user_dir, user_hash

    # Подсчитываем суммарный размер всех файлов в папке (рекурсивно)
    def get_dir_size(self, path):
        # Суммируем размер каждого файла во всех вложенных папках
        return sum(os.path.getsize(os.path.join(d, f))
                   for d, _, fs in os.walk(path) for f in fs)

    # Форматируем размер в человеко-читаемый вид (B → kB → MB → GB)
    def format_size(self, size):
        for unit in ['B', 'kB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f}{unit}"
            size /= 1024
        return f"{size:.1f}GB"

    def get_help_text(self, is_admin=False):
        text = (
            "команды:\n"
            "ls - список ссылок на файлы в папке пользователя.\n"
            "ls <-s> - простой список файлов. Пример: ls -s\n"
            "rm <номер>[,<номер>],.. - удаление файлов по его порядковому номеру или rm * - для удаления всех файлов.\n"
            "link <номер>[,<номер>],.. - получение ссылок на файлы по его номеру или lnk * - для получения ссылок всех файлов.\n"
            "ping - проверить доступность бота.\n"
            "help или ? - список команд.\n\n"
            "Бот принимает файлы ТОЛЬКО через Jingle (SOCKS5 Bytestreams)."
        )
        if is_admin:
            text += (
                "\n\n🔧 Админ-команды:\n"
                "add <jid|domain|*> - разрешить доступ (используйте * чтобы разрешить всем).\n"
                "del <jid|domain|*> - запретить доступ.\n"
                "list - показать белый список."
            )
        return text

    # Обработчик запроса на подписку
    def handle_presence_subscribe(self, presence):
        jid = presence['from'].bare
        logging.info(f"🆕 Запрос подписки от {jid}")

        # Уведомляем администратора
        if ADMIN_JID:
            self.send_message(mto=ADMIN_JID, mbody=f"➕ Пользователь {jid} отправил запрос на подписку", mtype='chat')

        # Автоматически подтверждаем подписку
        self.send_presence(pto=jid, ptype='subscribed')
        # И подписываемся в ответ
        self.send_presence(pto=jid, ptype='subscribe')

        # Приветственное сообщение
        is_admin = ADMIN_JID and jid == ADMIN_JID
        welcome_msg = f"Добро пожаловать!\nЯ бот для быстрой передачи файлов.\n\n{self.get_help_text(is_admin)}"
        self.send_message(mto=jid, mbody=welcome_msg, mtype='chat')

    # Обработчик подтверждения подписки
    def handle_presence_subscribed(self, presence):
        jid = presence['from'].bare
        logging.info(f"✅ Подписка подтверждена от {jid}")
        if ADMIN_JID:
            self.send_message(mto=ADMIN_JID, mbody=f"✅ Пользователь {jid} подтвердил подписку", mtype='chat')

    # Обработчик запроса на отмену подписки
    def handle_presence_unsubscribe(self, presence):
        jid = presence['from'].bare
        logging.info(f"➖ Запрос отписки от {jid}")
        if ADMIN_JID:
            self.send_message(mto=ADMIN_JID, mbody=f"➖ Пользователь {jid} удалил бота из контактов", mtype='chat')

    # Обработчик подтверждения отмены подписки
    def handle_presence_unsubscribed(self, presence):
        jid = presence['from'].bare
        logging.info(f"❌ Подписка отменена от {jid}")
        if ADMIN_JID:
            self.send_message(mto=ADMIN_JID, mbody=f"❌ Пользователь {jid} отменил подписку", mtype='chat')

    # Обработчик обычных текстовых сообщений
    def handle_message(self, msg):
        # Обрабатываем только личные сообщения с текстом
        if msg['type'] not in ('chat', 'normal') or not msg['body']:
            return

        # Проверка белого списка
        if not self.is_allowed(msg['from']):
            logging.info(f"ACCESS DENIED (msg) from {msg['from']}")
            if ADMIN_JID:
                self.send_message(mto=ADMIN_JID, mbody=f"🚫 Попытка сообщения от {msg['from']}", mtype='chat')
            return

        # Разбиваем сообщение на части
        parts = msg['body'].strip().split()
        if not parts:
            return
        cmd = parts[0].lower()

        # Получаем папку и хеш пользователя
        user_dir, user_hash = self.get_user_info(msg['from'])

        # Вспомогательная функция для ответов с новой строки
        def reply(text):
            self.send_message(mto=msg['from'], mbody=text, mtype='chat')

        # Команда помощи
        if cmd in ('help', '?'):
            if len(parts) != 1: return
            is_admin = ADMIN_JID and msg['from'].bare == ADMIN_JID
            used = self.get_dir_size(user_dir)
            help_text = self.get_help_text(is_admin) + f"\n\n📊 Квота: {self.format_size(used)} / {self.format_size(QUOTA_LIMIT_BYTES)}"
            reply(help_text)

        # Команда пинга
        elif cmd == 'ping':
            if len(parts) != 1: return
            reply("pong")

        # Команда показа списка файлов
        elif cmd == 'ls':
            if len(parts) > 2: return
            files = sorted(os.listdir(user_dir))
            if not files:
                return reply("📁 Папка пуста")

            if len(parts) == 2:
                if parts[1] == '-s':
                    res = []
                    for i, f in enumerate(files):
                        size = os.path.getsize(os.path.join(user_dir, f))
                        res.append(f"{i+1} - {f} [{self.format_size(size)}]")
                    reply("\n".join(res))
                return

            # По умолчанию (просто ls) - список ссылок через OOB
            for i, f in enumerate(files):
                url = f"{self.base_url}/{user_hash}/{self.safe_quote(f)}"
                self.send_message(mto=msg['from'], mbody=f"{i+1} - {url}", mtype='chat', oob_url=url)

        # Команда получения ссылки на файл
        elif cmd in ('link', 'lnk'):
            if len(parts) != 2: return
            files = sorted(os.listdir(user_dir))
            if not files:
                return reply("📁 Папка пуста")

            if parts[1] == '*':
                for i, f in enumerate(files):
                    url = f"{self.base_url}/{user_hash}/{self.safe_quote(f)}"
                    self.send_message(mto=msg['from'], mbody=f"{i+1} - {url}", mtype='chat', oob_url=url)
            else:
                try:
                    indices = sorted(list(set(int(p.strip()) - 1 for p in parts[1].split(',') if p.strip())))
                except ValueError: return

                for idx in indices:
                    if 0 <= idx < len(files):
                        f = files[idx]
                        url = f"{self.base_url}/{user_hash}/{self.safe_quote(f)}"
                        self.send_message(mto=msg['from'], mbody=f"{idx+1} - {url}", mtype='chat', oob_url=url)

        # Команда удаления файлов
        elif cmd == 'rm':
            if len(parts) != 2: return
            files = sorted(os.listdir(user_dir))
            if not files:
                return reply("📁 Папка пуста")

            if parts[1] == '*':
                for f in files:
                    os.remove(os.path.join(user_dir, f))
                reply("🗑 Все файлы удалены.")
            else:
                try:
                    indices = sorted(list(set(int(p.strip()) - 1 for p in parts[1].split(',') if p.strip())), reverse=True)
                except ValueError: return

                removed = []
                for idx in indices:
                    if 0 <= idx < len(files):
                        f = files[idx]
                        try:
                            os.remove(os.path.join(user_dir, f))
                            removed.append(f)
                        except OSError:
                            pass
                if removed:
                    reply(f"🗑 Удалено файлов: {len(removed)}")

        # Админ-команды для управления белым списком
        if ADMIN_JID and msg['from'].bare == ADMIN_JID:
            if cmd == 'add' and len(parts) == 2:
                entry = parts[1].lower()
                self.whitelist.add(entry)
                self.save_whitelist()
                if entry == '*':
                    reply("🌟 Доступ разрешён для ВСЕХ пользователей.")
                else:
                    reply(f"➕ Добавлено: {entry}")
            elif cmd == 'del' and len(parts) == 2:
                entry = parts[1].lower()
                if entry in self.whitelist:
                    self.whitelist.remove(entry)
                    self.save_whitelist()
                    reply(f"➖ Удалено: {entry}")
                else:
                    reply(f"❓ Не найдено: {entry}")
            elif cmd == 'list' and len(parts) == 1:
                res = "\n".join(sorted(self.whitelist))
                reply(f"📄 Белый список:\n{res or '(пусто)'}")







    # Обработчик XMPP Ping
    def handle_ping(self, iq):
        logging.info(f"PING RECV from {iq['from']}")
        reply = iq.reply()
        # Добавляем элемент <ping xmlns="urn:xmpp:ping"/> в ответ
        ping = ET.Element('{urn:xmpp:ping}ping')
        reply.append(ping)
        reply.send()
        logging.info(f"PONG SENT to {iq['from']}")


    # Общая логика SOCKS5 (для Jingle)
    async def _socks5_connect_and_save(self, sid, peer_jid, hosts, jingle_sid=None):
        try:
            file_info = self.pending_files.get(sid)
            if not file_info:
                logging.warning(f"SOCKS5: Unknown SID {sid}")
                return False

            # Вычисляем адрес SOCKS5 (SHA1 от SID + Initiator JID + Target JID)
            # В SI: initiator - отправитель, target - бот
            # В Jingle FT: initiator - отправитель, target - бот
            dst_addr = hashlib.sha1(
                f"{sid}{peer_jid.full}{self.boundjid.full}".encode()
            ).hexdigest()
            logging.info(f"SOCKS5: Calculated dst_addr={dst_addr} for sid={sid}")

            logging.info(f"SOCKS5: Found {len(hosts)} streamhosts")
            for host in hosts:
                h_host, h_port, h_jid = host['host'], host['port'], host['jid']
                logging.info(f"SOCKS5: Trying {h_host}:{h_port} ({h_jid})")
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(h_host, h_port),
                        5
                    )
                    logging.info(f"SOCKS5: TCP connected to {h_host}:{h_port}")

                    # Handshake
                    writer.write(b"\x05\x01\x00")
                    await writer.drain()
                    if (await reader.read(2)) != b"\x05\x00":
                        writer.close(); continue

                    # Connect
                    writer.write(b"\x05\x01\x00\x03" + bytes([len(dst_addr)]) + dst_addr.encode() + b"\x00\x00")
                    await writer.drain()
                    resp = await reader.read(4)
                    if not resp or resp[1] != 0x00:
                        writer.close(); continue

                    # Skip remain resp
                    atyp = resp[3]
                    if atyp == 0x01: await reader.read(6)
                    elif atyp == 0x03: a_len = await reader.read(1); await reader.read(a_len[0] + 2)
                    elif atyp == 0x04: await reader.read(18)

                    logging.info(f"SOCKS5: Connected to {h_host}")

                    # Для Jingle нужно отправить transport-info с candidate-used
                    if jingle_sid:
                        info = self.pending_files.get(sid)
                        if info:
                            iq = self.make_iq_set()
                            iq['to'] = peer_jid
                            jingle = ET.Element('{urn:xmpp:jingle:1}jingle', action='transport-info', sid=jingle_sid)
                            content = ET.SubElement(jingle, '{urn:xmpp:jingle:1}content', creator=info['content_creator'], name=info['content_name'])
                            transport = ET.SubElement(content, '{urn:xmpp:jingle:transports:s5b:1}transport', sid=sid)
                            ET.SubElement(transport, '{urn:xmpp:jingle:transports:s5b:1}candidate-used', jid=h_jid)
                            iq.append(jingle)
                            iq.send()
                            logging.info(f"Jingle transport-info SENT: sid={jingle_sid}, candidate={h_jid}")

                    await self.save_file_task(reader, file_info, peer_jid, sid_to_clean=sid)
                    writer.close()
                    await writer.wait_closed()
                    return True

                except Exception as e:
                    logging.warning(f"SOCKS5: Error with {h_host}: {e}")
                    continue

            return False
        except Exception as e:
            logging.error(f"SOCKS5 GENERIC ERROR: {e}")
            return False

    # Асинхронная функция непосредственного приёма данных файла
    async def save_file_task(self, stream, file_info, peer_jid, sid_to_clean=None):
        user_dir, user_hash = self.get_user_info(peer_jid)
        # Имя файла уже санитизировано в handle_jingle_initiate
        fname = file_info['name']
        path = os.path.join(user_dir, fname)
        received = 0
        logging.info(f"DOWNLOAD START: {fname} to {path}")

        try:
            with open(path, 'wb') as f:
                while received < file_info['size']:
                    # Стрим может иметь другой интерфейс чтения
                    if hasattr(stream, 'read'):
                        chunk = await stream.read(min(file_info['size'] - received, 1048576))
                    elif hasattr(stream, 'recv'):
                        chunk = await stream.recv()
                    else:
                        logging.error(f"DOWNLOAD ERROR: Stream object has no read/recv: {type(stream)}")
                        break

                    if not chunk:
                        logging.warning(f"DOWNLOAD: STREAM ENDED EARLY for {fname}: got {received}/{file_info['size']}")
                        break
                    await asyncio.get_event_loop().run_in_executor(None, f.write, chunk)
                    received += len(chunk)
                    logging.debug(f"DOWNLOAD: WROTE CHUNK sid={sid_to_clean}, chunk_len={len(chunk)}, total={received}")
                    if received % 1048576 == 0:
                         logging.info(f"DOWNLOAD PROGRESS: {fname} {received}/{file_info['size']}")

                f.flush()
                await asyncio.get_event_loop().run_in_executor(None, os.fsync, f.fileno())

            # Если всё получили полностью — сообщаем пользователю ссылку
            if received == file_info['size']:
                logging.info(f"DOWNLOAD COMPLETE: {fname}, {received} bytes")
                safe_name = self.safe_quote(fname)
                url = f"{self.base_url}/{user_hash}/{safe_name}"
                self.send_message(
                    mto=peer_jid,
                    mbody=f"✅ Готово!\n{url}",
                    mtype='chat',
                    oob_url=url
                )
            else:
                logging.warning(f"DOWNLOAD INCOMPLETE: {fname}, got {received}/{file_info['size']}. Deleting.")
                if os.path.exists(path):
                    os.remove(path)

        except Exception as e:
            logging.error(f"Ошибка при приёме файла: {e}")
            if os.path.exists(path):
                os.remove(path)
        finally:
            if sid_to_clean and sid_to_clean in self.pending_files:
                del self.pending_files[sid_to_clean]



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
