# Импорт модуля для работы с операционной системой (пути, файлы, окружение)
import os

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
VERSION = "1.1"


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

        # Белый список
        self.whitelist = set()
        self.load_whitelist()

        # Регистрируем плагин XEP-0030 (Service Discovery)
        self.register_plugin('xep_0030')
        # Регистрируем плагин XEP-0199 (XMPP Ping)
        self.register_plugin('xep_0199')
        # Регистрируем плагин XEP-0092 (Software Version)
        self.register_plugin('xep_0092')
        self['xep_0092'].software_name = 'OBBFastBot'
        self['xep_0092'].version = VERSION

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

    # Красивое кодирование URL (сохраняем кириллицу для читаемости)
    def safe_quote(self, text):
        return "".join(c if ord(c) >= 128 or c.isalnum() or c in ' ._-~/:?=&'
                       else urllib.parse.quote(c) for c in text)

    def send_message(self, mto, mbody, msubject=None, mtype=None, mhtml=None,
                     mfrom=None, mnick=None):
        if mbody and not mbody.startswith('\n'):
            mbody = '\n' + mbody
        super().send_message(mto, mbody, msubject, mtype, mhtml, mfrom, mnick)

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

    def get_help_text(self):
        return (
            "команды:\n"
            "ls - список ссылок на файлы в папке пользователя.\n"
            "ls <-s> - простой список файлов. Пример: ls -s\n"
            "rm <номер>[,<номер>],.. - удаление файлов по его порядковому номеру или rm * - для удаления всех файлов.\n"
            "link <номер>[,<номер>],.. - получение ссылок на файлы по его номеру или lnk * - для получения ссылок всех файлов.\n"
            "help или ? - список команд."
        )

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
        welcome_msg = f"Добро пожаловать!\nЯ бот для быстрой передачи файлов.\n\n{self.get_help_text()}"
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
            used = self.get_dir_size(user_dir)
            help_text = self.get_help_text() + f"\n\n📊 Квота: {self.format_size(used)} / {self.format_size(QUOTA_LIMIT_BYTES)}"
            reply(help_text)

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

            # По умолчанию (просто ls) - список ссылок
            res = []
            for i, f in enumerate(files):
                res.append(f"{i+1} - {self.base_url}/{user_hash}/{self.safe_quote(f)}")
            reply("\n".join(res))

        # Команда получения ссылки на файл
        elif cmd in ('link', 'lnk'):
            if len(parts) != 2: return
            files = sorted(os.listdir(user_dir))
            if not files:
                return reply("📁 Папка пуста")

            if parts[1] == '*':
                res = []
                for i, f in enumerate(files):
                    res.append(f"{i+1} - {self.base_url}/{user_hash}/{self.safe_quote(f)}")
                reply("\n".join(res))
            else:
                try:
                    indices = sorted(list(set(int(p.strip()) - 1 for p in parts[1].split(',') if p.strip())))
                except ValueError: return

                res = []
                for idx in indices:
                    if 0 <= idx < len(files):
                        f = files[idx]
                        res.append(f"{idx+1} - {self.base_url}/{user_hash}/{self.safe_quote(f)}")
                if res:
                    reply("\n".join(res))

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
            fname = os.path.basename(tag.get('name'))
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
                'timestamp': asyncio.get_event_loop().time()
            }

            # Формируем ответ: соглашаемся на SOCKS5
            reply = iq.reply()
            res_si = ET.Element('{http://jabber.org/protocol/si}si', {'id': sid})
            feature = ET.SubElement(res_si, '{http://jabber.org/protocol/feature-neg}feature')
            x = ET.SubElement(feature, '{jabber:x:data}x', type='submit')
            field = ET.SubElement(x, '{jabber:x:data}field', var='stream-method')
            ET.SubElement(field, '{jabber:x:data}value').text = 'http://jabber.org/protocol/bytestreams'

            reply.append(res_si)
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

    # Асинхронная функция подключения по SOCKS5 и приёма файла
    async def _manual_socks5_connect(self, iq):
        sid = None
        try:
            query = iq.xml.find('{http://jabber.org/protocol/bytestreams}query')
            if query is None:
                logging.error(f"SOCKS5: Query element not found in IQ: {iq}")
                return
            sid = query.get('sid')
            file_info = self.pending_files.get(sid)

            if not file_info:
                logging.warning(f"SOCKS5: Unknown SID {sid}")
                return

            # Вычисляем адрес SOCKS5 в соответствии со спецификацией
            dst_addr = hashlib.sha1(
                f"{sid}{iq['from'].full}{self.boundjid.full}".encode()
            ).hexdigest()
            logging.info(f"SOCKS5: Calculated dst_addr={dst_addr} for sid={sid}")

            # Пробуем каждый предложенный streamhost по очереди
            hosts = query.findall('{http://jabber.org/protocol/bytestreams}streamhost')
            logging.info(f"SOCKS5: Found {len(hosts)} streamhosts")
            for host in hosts:
                h_host, h_port, h_jid = host.get('host'), int(host.get('port', 1080)), host.get('jid')
                logging.info(f"SOCKS5: Trying host {h_host}:{h_port} ({h_jid})")
                try:
                    # Устанавливаем TCP-соединение
                    logging.info(f"SOCKS5: Opening connection to {h_host}:{h_port}")
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(h_host, h_port),
                        5
                    )
                    logging.info(f"SOCKS5: TCP connected to {h_host}:{h_port}")

                    # SOCKS5 handshake: без аутентификации
                    writer.write(b"\x05\x01\x00")
                    await writer.drain()

                    handshake_resp = await reader.read(2)
                    if handshake_resp != b"\x05\x00":
                        logging.warning(f"SOCKS5: Handshake failed for {h_host}: {handshake_resp}")
                        writer.close()
                        continue

                    # Запрос на соединение с вычисленным адресом
                    writer.write(b"\x05\x01\x00\x03" + bytes([len(dst_addr)]) + dst_addr.encode() + b"\x00\x00")
                    await writer.drain()

                    resp = await reader.read(4)
                    if not resp or resp[1] != 0x00:
                        logging.warning(f"SOCKS5: Connection request failed for {h_host}: {resp}")
                        writer.close()
                        continue

                    # Пропускаем остаток ответа в зависимости от типа адреса
                    atyp = resp[3]
                    if atyp == 0x01:    await reader.read(6)
                    elif atyp == 0x03:  addr_len = await reader.read(1); await reader.read(addr_len[0] + 2)
                    elif atyp == 0x04:  await reader.read(18)

                    # Отвечаем, что используем именно этот streamhost
                    logging.info(f"SOCKS5: Connected to {h_host}, sending streamhost-used")
                    reply = iq.reply()
                    res_q = ET.Element('{http://jabber.org/protocol/bytestreams}query', {'sid': sid})
                    ET.SubElement(res_q, 'streamhost-used', jid=h_jid)
                    reply.append(res_q)
                    reply.send()

                    # Запускаем приём файла
                    await self.download_file_task(reader, file_info, iq['from'])

                    writer.close()
                    await writer.wait_closed()
                    return

                except asyncio.TimeoutError:
                    logging.warning(f"SOCKS5: Timeout connecting to {h_host}:{h_port}")
                    continue
                except Exception as e:
                    logging.warning(f"SOCKS5: Error with host {h_host}: {e}")
                    continue

            # Если ни один прокси не сработал — ошибка
            logging.error(f"SOCKS5: All streamhosts failed for sid={sid}")
            reply = iq.reply()
            reply['type'] = 'error'
            reply.send()

        except Exception as e:
            logging.error(f"SOCKS5 ERROR: {e}")
        finally:
            if sid in self.pending_files:
                del self.pending_files[sid]

    # Асинхронная функция непосредственного приёма данных файла
    async def download_file_task(self, reader, file_info, peer_jid):
        user_dir, user_hash = self.get_user_info(peer_jid)
        # Санитизируем имя файла ещё раз при формировании пути
        fname = os.path.basename(file_info['name'])
        path = os.path.join(user_dir, fname)
        received = 0
        logging.info(f"DOWNLOAD START: {file_info['name']} to {path}")

        try:
            with open(path, 'wb') as f:
                while received < file_info['size']:
                    # Читаем кусок до 1 МБ
                    chunk = await reader.read(min(file_info['size'] - received, 1048576))
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)

                f.flush()
                os.fsync(f.fileno())

            # Если всё получили полностью — сообщаем пользователю ссылку
            if received == file_info['size']:
                logging.info(f"DOWNLOAD COMPLETE: {file_info['name']}, {received} bytes")
                safe_name = self.safe_quote(file_info['name'])
                self.send_message(
                    mto=peer_jid,
                    mbody=f"✅ Готово!\n{self.base_url}/{user_hash}/{safe_name}",
                    mtype='chat'
                )
            else:
                # Если файл не докачан — удаляем его, чтобы не занимал квоту
                logging.warning(f"DOWNLOAD INCOMPLETE: {file_info['name']}, got {received}/{file_info['size']}. Deleting.")
                if os.path.exists(path):
                    os.remove(path)

        except Exception as e:
            # При любой ошибке удаляем файл
            logging.error(f"Ошибка при приёме файла: {e}")
            if os.path.exists(path):
                os.remove(path)


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
