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

# Импорт модуля aiohttp для реализации HTTP Upload
from aiohttp import web

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
        self.register_plugin('xep_0047') # IBB
        self.register_plugin('xep_0066') # OOB
        self.register_plugin('xep_0234') # Jingle File Transfer

        # Подписываемся на событие успешного входа в сеть
        self.add_event_handler("session_start", self.start)

        # Подписываемся на входящие сообщения (chat / normal)
        self.add_event_handler("message", self.handle_message)

        # Обработчики для IBB
        self.add_event_handler("ibb_stream_start", self.handle_ibb_stream)

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


        # Явный обработчик для HTTP Upload (XEP-0363)
        self.register_handler(handler.Callback('HTTPUpload',
            matcher.MatchXPath('{jabber:client}iq/{urn:xmpp:http:upload:0}request'),
            self.handle_http_upload))

        # Явный обработчик для OOB (XEP-0066)
        self.register_handler(handler.Callback('OOB',
            matcher.MatchXPath('{jabber:client}iq/{jabber:iq:oob}query'),
            self.handle_oob))

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
            if ADMIN_JID:
                self.send_message(mto=ADMIN_JID, mbody=f"🚫 Попытка Jingle передачи от {peer_jid}", mtype='chat')
            reply = iq.reply()
            reply['type'] = 'error'
            reply['error']['condition'] = 'forbidden'
            return reply.send()

        try:
            content = jingle.find('{urn:xmpp:jingle:1}content')
            description = content.find('{urn:xmpp:jingle:apps:file-transfer:5}description')
            file_tag = description.find('{urn:xmpp:jingle:apps:file-transfer:5}file')

            fname = os.path.basename(file_tag.findtext('{urn:xmpp:jingle:apps:file-transfer:5}name')).replace(' ', '_')
            fsize = int(file_tag.findtext('{urn:xmpp:jingle:apps:file-transfer:5}size') or 0)

            user_dir, _ = self.get_user_info(peer_jid)
            if self.get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                logging.info(f"QUOTA EXCEEDED for {peer_jid}")
                self.send_message(mto=peer_jid, mbody="⚠ Квота превышена!", mtype='chat')
                reply = iq.reply()
                reply['type'] = 'error'
                reply['error']['condition'] = 'not-acceptable'
                return reply.send()

            self.pending_files[sid] = {
                'name': fname,
                'size': fsize,
                'from': peer_jid.bare,
                'timestamp': asyncio.get_event_loop().time(),
                'jingle': True
            }

            # Предпочитаем IBB для передачи без прокси
            transport_ibb = content.find('{urn:xmpp:jingle:transports:ibb:1}transport')
            transport_s5b = content.find('{urn:xmpp:jingle:transports:s5b:1}transport')

            if transport_ibb is not None:
                await self.accept_jingle_ibb(iq, sid, transport_ibb)
            elif transport_s5b is not None:
                await self.accept_jingle_s5b(iq, sid, transport_s5b)
            else:
                reply = iq.reply()
                reply['type'] = 'error'
                reply['error']['condition'] = 'feature-not-implemented'
                reply.send()

        except Exception as e:
            logging.error(f"JINGLE INITIATE ERROR: {e}")
            reply = iq.reply()
            reply['type'] = 'error'
            reply.send()

    async def accept_jingle_ibb(self, iq, sid, transport):
        block_size = transport.get('block-size', '4096')
        ibb_sid = transport.get('sid', sid)

        # Переносим инфу о файле на IBB SID если он отличается
        if ibb_sid != sid:
            self.pending_files[ibb_sid] = self.pending_files[sid]

        reply = iq.reply()
        jingle = ET.Element('{urn:xmpp:jingle:1}jingle', action='session-accept', sid=sid, responder=self.boundjid.full)
        content = ET.SubElement(jingle, 'content', creator='initiator', name='file-transfer')
        ET.SubElement(content, '{urn:xmpp:jingle:apps:file-transfer:5}description')
        ET.SubElement(content, '{urn:xmpp:jingle:transports:ibb:1}transport', sid=ibb_sid, block_size=block_size)
        reply.append(jingle)
        reply.send()
        logging.info(f"Jingle session accepted (IBB): sid={sid}, ibb_sid={ibb_sid}")

    async def accept_jingle_s5b(self, iq, sid, transport):
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
        content = ET.SubElement(jingle, 'content', creator='initiator', name='file-transfer')
        ET.SubElement(content, '{urn:xmpp:jingle:apps:file-transfer:5}description')
        ET.SubElement(content, '{urn:xmpp:jingle:transports:s5b:1}transport', sid=dst_sid)
        reply.append(jingle)
        reply.send()
        logging.info(f"Jingle session accepted (S5B): sid={sid}, dst_sid={dst_sid}")

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

        # Сообщаем серверу, что мы поддерживаем SI (Stream Initiation)
        self['xep_0030'].add_feature('http://jabber.org/protocol/si')

        # Сообщаем, что поддерживаем SOCKS5 Bytestreams
        self['xep_0030'].add_feature('http://jabber.org/protocol/bytestreams')

        # Указываем, что поддерживаем профиль передачи файлов через SI
        self['xep_0030'].add_feature('http://jabber.org/protocol/si/profile/file-transfer')

        # Поддержка IBB
        self['xep_0030'].add_feature('http://jabber.org/protocol/ibb')

        # Поддержка HTTP Upload (XEP-0363)
        self['xep_0030'].add_feature('urn:xmpp:http:upload:0')

        # Поддержка OOB (XEP-0066)
        self['xep_0030'].add_feature('jabber:iq:oob')
        self['xep_0030'].add_feature('jabber:x:oob')

        # Поддержка Jingle (XEP-0166) и Jingle File Transfer (XEP-0234)
        self['xep_0030'].add_feature('urn:xmpp:jingle:1')
        self['xep_0030'].add_feature('urn:xmpp:jingle:apps:file-transfer:5')
        self['xep_0030'].add_feature('urn:xmpp:jingle:transports:s5b:1')
        self['xep_0030'].add_feature('urn:xmpp:jingle:transports:ibb:1')

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
            "help или ? - список команд."
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

    # Обработчик входящего SI (Stream Initiation) запроса на передачу файла
    def handle_raw_si(self, iq):
        logging.info(f"SI XML RECV: {iq}")
        # Проверка белого списка
        if not self.is_allowed(iq['from']):
            logging.info(f"ACCESS DENIED (SI) from {iq['from']}")
            if ADMIN_JID:
                self.send_message(mto=ADMIN_JID, mbody=f"🚫 Попытка передачи файла от {iq['from']}", mtype='chat')
            reply = iq.reply()
            reply['type'] = 'error'
            return reply.send()

        try:
            # Находим элемент <si>
            si = iq.xml.find('{http://jabber.org/protocol/si}si')

            # ID сессии передачи и элемент <file>
            sid, tag = si.get('id'), si.find('{http://jabber.org/protocol/si/profile/file-transfer}file')

            # Имя и размер файла, который хочет отправить собеседник
            # Санитизируем имя файла для предотвращения Path Traversal
            # Заменяем пробелы на подчёркивания
            fname = os.path.basename(tag.get('name')).replace(' ', '_')
            fsize = int(tag.get('size', 0))
            logging.info(f"SI REQUEST: {fname} ({fsize} bytes) from {iq['from']}, sid={sid}")

            user_dir, _ = self.get_user_info(iq['from'])

            # Проверяем, хватит ли места в квоте
            if self.get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                logging.info(f"QUOTA EXCEEDED for {iq['from']}")
                self.send_message(mto=iq['from'], mbody="⚠ Квота превышена!", mtype='chat')
                reply = iq.reply()
                reply['type'] = 'error'
                return reply.send()

            # Запоминаем информацию о файле, который сейчас будут передавать
            self.pending_files[sid] = {
                'name': fname,
                'size': fsize,
                'from': iq['from'].bare,
                'timestamp': asyncio.get_event_loop().time()
            }

            # Определяем подходящий метод передачи из предложенных (с защитой от отсутствующих полей)
            options = []
            feature_neg = si.find('{http://jabber.org/protocol/feature-neg}feature')
            if feature_neg is not None:
                x_data = feature_neg.find('{jabber:x:data}x')
                if x_data is not None:
                    field = x_data.find('{jabber:x:data}field[@var="stream-method"]')
                    if field is not None:
                        options = [v.text for v in field.findall('{jabber:x:data}value')]

            # Так как S5B часто не срабатывает, пробуем отдавать приоритет OOB или IBB если они предложены
            if 'jabber:iq:oob' in options:
                method = 'jabber:iq:oob'
            elif 'http://jabber.org/protocol/ibb' in options:
                method = 'http://jabber.org/protocol/ibb'
            elif 'http://jabber.org/protocol/bytestreams' in options:
                method = 'http://jabber.org/protocol/bytestreams'
            else:
                # Если ничего не нашли - пробуем S5B как наиболее вероятный дефолт
                method = 'http://jabber.org/protocol/bytestreams'

            # Формируем ответ
            reply = iq.reply()
            res_si = ET.Element('{http://jabber.org/protocol/si}si', {'id': sid})
            feature = ET.SubElement(res_si, '{http://jabber.org/protocol/feature-neg}feature')
            x = ET.SubElement(feature, '{jabber:x:data}x', type='submit')
            field = ET.SubElement(x, '{jabber:x:data}field', var='stream-method')
            ET.SubElement(field, '{jabber:x:data}value').text = method

            # Обработка OOB в SI
            if method == 'jabber:iq:oob':
                # Для OOB в SI мы просто ожидаем, что клиент пришлет IQ jabber:iq:oob позже,
                # либо сразу отвечаем подтверждением метода.
                pass

            reply.append(res_si)
            logging.info(f"SI XML SEND (choice): {reply}")
            reply.send()

        except Exception as e:
            logging.error(f"SI ERROR: {e}")
            # Если что-то сломалось — молча игнорируем (не отвечаем)
            pass

    # Обработчик входящего запроса SOCKS5 Bytestreams
    def handle_raw_s5b(self, iq):
        logging.info(f"S5B REQUEST from {iq['from']}")
        # Запускаем асинхронную задачу обработки SOCKS5
        asyncio.create_task(self._manual_socks5_connect(iq))

    # Обработчик начала IBB стрима
    def handle_ibb_stream(self, stream):
        sid = stream.sid
        file_info = self.pending_files.get(sid)
        if file_info:
            logging.info(f"IBB STREAM START: sid={sid}")
            asyncio.create_task(self.save_file_task(stream, file_info, file_info['from'], sid_to_clean=sid))
        else:
            logging.warning(f"IBB STREAM: Unknown SID {sid}")


    # Обработчик запроса на HTTP Upload (XEP-0363)
    def handle_http_upload(self, iq):
        try:
            req = iq.xml.find('{urn:xmpp:http:upload:0}request')
            fname = req.get('filename')
            fsize = int(req.get('size', 0))

            # Санитизируем
            fname = os.path.basename(fname).replace(' ', '_')

            # Проверка белого списка
            if not self.is_allowed(iq['from']):
                reply = iq.reply(); reply['type'] = 'error'; return reply.send()

            # Проверка квоты
            user_dir, user_hash = self.get_user_info(iq['from'])
            if self.get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                reply = iq.reply(); reply['type'] = 'error'; return reply.send()

            # Генерируем уникальный токен для PUT
            token = hashlib.sha256(f"{iq['from'].full}{fname}{fsize}{asyncio.get_event_loop().time()}".encode()).hexdigest()[:16]

            # Запоминаем для сопоставления при PUT запросе
            self.pending_files[token] = {
                'name': fname,
                'size': fsize,
                'from': iq['from'].bare,
                'timestamp': asyncio.get_event_loop().time()
            }

            # Формируем ответ со ссылками
            reply = iq.reply()
            slot = ET.Element('{urn:xmpp:http:upload:0}slot')

            put_url = f"{self.base_url}/upload/{token}/{fname}"
            get_url = f"{self.base_url}/{user_hash}/{self.safe_quote(fname)}"

            put = ET.SubElement(slot, 'put')
            put.set('url', put_url)

            get = ET.SubElement(slot, 'get')
            get.set('url', get_url)

            reply.append(slot)
            reply.send()
            logging.info(f"HTTP UPLOAD slot generated for {fname} ({fsize} bytes)")

        except Exception as e:
            logging.error(f"HTTP UPLOAD ERROR: {e}")

    # Обработчик запроса на OOB (XEP-0066)
    def handle_oob(self, iq):
        # Проверка белого списка
        if not self.is_allowed(iq['from']):
            reply = iq.reply(); reply['type'] = 'error'; return reply.send()

        try:
            query = iq.xml.find('{jabber:iq:oob}query')
            url = query.find('{jabber:iq:oob}url').text
            fname = query.find('{jabber:iq:oob}desc')
            if fname is not None:
                fname = fname.text
            else:
                fname = os.path.basename(urllib.parse.urlparse(url).path)

            # Санитизируем
            fname = os.path.basename(fname).replace(' ', '_')
            if not fname: fname = "downloaded_file"

            logging.info(f"OOB REQUEST: {url} as {fname} from {iq['from']}")

            # Запускаем задачу загрузки
            asyncio.create_task(self.download_oob_task(url, fname, iq['from']))

            # Отвечаем успехом (подтверждаем получение IQ)
            iq.reply().send()

        except Exception as e:
            logging.error(f"OOB ERROR: {e}")
            reply = iq.reply(); reply['type'] = 'error'; reply.send()

    # Асинхронная задача загрузки файла по URL
    async def download_oob_task(self, url, fname, peer_jid):
        user_dir, user_hash = self.get_user_info(peer_jid)
        path = os.path.join(user_dir, fname)

        logging.info(f"OOB DOWNLOAD START: {url} to {path}")

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=300) as resp:
                    if resp.status != 200:
                        logging.error(f"OOB DOWNLOAD FAILED: status {resp.status}")
                        return

                    # Проверка квоты (размер может быть неизвестен заранее, проверяем по ходу)
                    content_length = resp.headers.get('Content-Length')
                    fsize = int(content_length) if content_length else 0

                    if fsize and self.get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                        self.send_message(mto=peer_jid, mbody="⚠ Квота превышена!", mtype='chat')
                        return

                    received = 0
                    with open(path, 'wb') as f:
                        async for chunk in resp.content.iter_chunked(1048576):
                            if self.get_dir_size(user_dir) + received + len(chunk) > QUOTA_LIMIT_BYTES:
                                self.send_message(mto=peer_jid, mbody="⚠ Квота превышена в процессе загрузки!", mtype='chat')
                                f.close()
                                os.remove(path)
                                return

                            await asyncio.get_event_loop().run_in_executor(None, f.write, chunk)
                            received += len(chunk)

                        f.flush()
                        await asyncio.get_event_loop().run_in_executor(None, os.fsync, f.fileno())

            logging.info(f"OOB DOWNLOAD COMPLETE: {fname}, {received} bytes")
            safe_name = self.safe_quote(fname)
            self.send_message(
                mto=peer_jid,
                mbody=f"✅ Готово (OOB)!\n{self.base_url}/{user_hash}/{safe_name}",
                mtype='chat'
            )

        except Exception as e:
            logging.error(f"OOB DOWNLOAD ERROR: {e}")
            if os.path.exists(path): os.remove(path)


    # Обработчик XMPP Ping
    def handle_ping(self, iq):
        logging.info(f"PING RECV from {iq['from']}")
        reply = iq.reply()
        # Добавляем элемент <ping xmlns="urn:xmpp:ping"/> в ответ
        ping = ET.Element('{urn:xmpp:ping}ping')
        reply.append(ping)
        reply.send()
        logging.info(f"PONG SENT to {iq['from']}")

    # Асинхронная функция подключения по SOCKS5 и приёма файла
    async def _manual_socks5_connect(self, iq):
        try:
            query = iq.xml.find('{http://jabber.org/protocol/bytestreams}query')
            if query is None:
                logging.error(f"SOCKS5: Query element not found in IQ: {iq}")
                return
            sid = query.get('sid')

            # Собираем список хостов из SI запроса
            hosts = []
            for host in query.findall('{http://jabber.org/protocol/bytestreams}streamhost'):
                hosts.append({
                    'host': host.get('host'),
                    'port': int(host.get('port', 1080)),
                    'jid': host.get('jid')
                })

            # Запускаем общую логику подключения
            success = await self._socks5_connect_and_save(sid, iq['from'], hosts, iq_for_si_reply=iq)

            if not success:
                # Если ни один прокси не сработал — ошибка SI
                if not hosts:
                    self.send_message(
                        mto=iq['from'].bare,
                        mbody="⚠ Не найдено доступных путей для передачи (SOCKS5). "
                              "Бот пробует переключиться на IBB...",
                        mtype='chat'
                    )
                reply = iq.reply()
                reply['type'] = 'error'
                reply['error']['condition'] = 'item-not-found'
                reply['error']['text'] = 'SOCKS5 failed'
                reply.send()

        except Exception as e:
            logging.error(f"SOCKS5 SI ERROR: {e}")

    # Общая логика SOCKS5 (для SI и Jingle)
    async def _socks5_connect_and_save(self, sid, peer_jid, hosts, iq_for_si_reply=None, jingle_sid=None):
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

                    # Для SI нужно отправить подтверждение streamhost-used
                    if iq_for_si_reply:
                        reply = iq_for_si_reply.reply()
                        res_q = ET.Element('{http://jabber.org/protocol/bytestreams}query', {'sid': sid})
                        ET.SubElement(res_q, 'streamhost-used', jid=h_jid)
                        reply.append(res_q)
                        reply.send()

                    # Для Jingle нужно отправить transport-info с candidate-used
                    if jingle_sid:
                        iq = self.make_iq_set()
                        iq['to'] = peer_jid
                        jingle = ET.Element('{urn:xmpp:jingle:1}jingle', action='transport-info', sid=jingle_sid)
                        content = ET.SubElement(jingle, 'content', creator='initiator', name='file-transfer')
                        transport = ET.SubElement(content, '{urn:xmpp:jingle:transports:s5b:1}transport', sid=sid)
                        ET.SubElement(transport, 'candidate-used', jid=h_jid)
                        iq.append(jingle)
                        iq.send()

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

    # Асинхронная функция непосредственного приёма данных файла (общая для SOCKS5 и IBB)
    async def save_file_task(self, stream, file_info, peer_jid, sid_to_clean=None):
        user_dir, user_hash = self.get_user_info(peer_jid)
        # Имя файла уже санитизировано в handle_raw_si
        fname = file_info['name']
        path = os.path.join(user_dir, fname)
        received = 0
        logging.info(f"DOWNLOAD START: {fname} to {path}")

        try:
            with open(path, 'wb') as f:
                while received < file_info['size']:
                    # IBB stream может иметь другой интерфейс чтения
                    if hasattr(stream, 'read'):
                        chunk = await stream.read(min(file_info['size'] - received, 1048576))
                    elif hasattr(stream, 'recv'):
                        chunk = await stream.recv()
                    else:
                        break

                    if not chunk:
                        break
                    await asyncio.get_event_loop().run_in_executor(None, f.write, chunk)
                    received += len(chunk)

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


# Обработчик PUT-запросов для HTTP Upload
async def handle_upload_put(request):
    token = request.match_info.get('token')
    bot = request.app['bot']

    info = bot.pending_files.get(token)
    if not info:
        return web.Response(status=404, text="Unknown token")

    user_dir, user_hash = bot.get_user_info(slixmpp.JID(info['from']))
    path = os.path.join(user_dir, info['name'])

    logging.info(f"HTTP PUT upload started: {info['name']} for {info['from']}")

    try:
        # Поскольку request.content.read() асинхронный, мы не можем просто обернуть весь цикл в executor.
        # Будем выполнять в executor только блокирующую операцию записи.
        with open(path, 'wb') as f:
            while True:
                chunk = await request.content.read(1048576)
                if not chunk:
                    break
                await asyncio.get_event_loop().run_in_executor(None, f.write, chunk)

        # Уведомляем пользователя
        url = f"{bot.base_url}/{user_hash}/{bot.safe_quote(info['name'])}"
        bot.send_message(
            mto=info['from'],
            mbody=f"✅ Готово (HTTP)!\n{url}",
            mtype='chat',
            oob_url=url
        )
        del bot.pending_files[token]
        return web.Response(status=201)

    except Exception as e:
        logging.error(f"HTTP PUT ERROR: {e}")
        if os.path.exists(path): os.remove(path)
        return web.Response(status=500)

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

    # Настраиваем HTTP Upload сервер
    app = web.Application()
    app['bot'] = bot
    app.router.add_put('/upload/{token}/{filename}', handle_upload_put)

    upload_port = int(os.getenv('HTTP_UPLOAD_PORT', 8080))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', upload_port)
    await site.start()
    logging.info(f"🌍 HTTP Upload server started on port {upload_port}")

    # Ждём отключения (работаем до разрыва соединения)
    await bot.disconnected


# Запуск программы
if __name__ == '__main__':
    # Запускаем асинхронный цикл событий
    asyncio.run(main())
