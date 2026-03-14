import os
import platform
import logging
import asyncio
import hashlib
import datetime
import shutil

from slixmpp import ClientXMPP
from slixmpp.xmlstream import ET, handler, matcher

from config import (
    ADMIN_JID, ADMIN_NOTIFY_LEVEL, QUOTA_LIMIT_BYTES,
    MAX_DIR_DEPTH, WHITELIST_FILE, VERSION, APP_NAME,
    STATUS_MESSAGE, BASE_URL
)
from database import Database
from utils import (
    format_size, get_dir_size, safe_quote, get_safe_path,
    get_unique_path, resolve_item, resolve_items_list, get_all_items
)

class OBBFastBot(ClientXMPP):
    def __init__(self, jid, password, dest_dir):
        super().__init__(jid, password)
        self.dest_dir = dest_dir
        self.base_url = BASE_URL
        self.pending_files = {}
        asyncio.create_task(self.cleanup_pending_files())

        self.db = Database()
        self.migrate_json_to_db()
        self.migrate_filenames()

        self.register_plugin('xep_0030')
        self.register_plugin('xep_0199')
        self['xep_0199'].send_keepalive = True
        self['xep_0199'].interval = 60
        self.register_plugin('xep_0092')
        self['xep_0092'].software_name = APP_NAME

        import slixmpp
        self['xep_0092'].version = f"{VERSION} on Python {platform.python_version()} + slixmpp {slixmpp.__version__}"

        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.handle_message)
        self.add_event_handler("presence_subscribe", self.handle_presence_subscribe)
        self.add_event_handler("presence_subscribed", self.handle_presence_subscribed)
        self.add_event_handler("presence_unsubscribe", self.handle_presence_unsubscribe)
        self.add_event_handler("presence_unsubscribed", self.handle_presence_unsubscribed)

        self.register_handler(handler.Callback('SI',
            matcher.MatchXPath('{jabber:client}iq/{http://jabber.org/protocol/si}si'),
            self.handle_raw_si))
        self.register_handler(handler.Callback('S5B',
            matcher.MatchXPath('{jabber:client}iq/{http://jabber.org/protocol/bytestreams}query'),
            self.handle_raw_s5b))
        self.register_handler(handler.Callback('Ping',
            matcher.MatchXPath('{jabber:client}iq/{urn:xmpp:ping}ping'),
            self.handle_ping))

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

    async def start(self, event):
        self['xep_0030'].add_feature('http://jabber.org/protocol/si')
        self['xep_0030'].add_feature('http://jabber.org/protocol/bytestreams')
        self['xep_0030'].add_feature('http://jabber.org/protocol/si/profile/file-transfer')
        self.send_presence(pstatus=STATUS_MESSAGE)
        await self.get_roster()
        logging.info(f"✅ БОТ ЗАПУЩЕН: {self.boundjid}")

    def migrate_json_to_db(self):
        try:
            if os.path.exists(WHITELIST_FILE):
                if os.path.isfile(WHITELIST_FILE):
                    import json
                    with open(WHITELIST_FILE, 'r') as f:
                        data = json.load(f)
                        for entry in data:
                            self.db.add_to_whitelist(entry)
                    logging.info(f"MIGRATED {len(data)} entries from {WHITELIST_FILE} to database")
                    os.remove(WHITELIST_FILE)
                elif os.path.isdir(WHITELIST_FILE):
                    os.rmdir(WHITELIST_FILE)
        except Exception as e:
            logging.error(f"MIGRATION ERROR: {e}")

    def is_allowed(self, jid):
        bare_jid = jid.bare.lower()
        if ADMIN_JID and bare_jid == ADMIN_JID.lower():
            return True

        blacklist = self.db.get_blacklist()
        if bare_jid in blacklist or jid.domain.lower() in blacklist:
            return False

        whitelist = self.db.get_whitelist()
        if '*' in whitelist:
            return True

        domain = jid.domain.lower()
        return bare_jid in whitelist or domain in whitelist

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

    def get_user_info(self, jid):
        bare_jid = jid.bare.lower()
        user_hash = self.db.get_user_folder(bare_jid)
        is_new = False
        if not user_hash:
            user_hash = hashlib.md5(bare_jid.encode()).hexdigest()
            self.db.set_user_folder(bare_jid, user_hash)
            is_new = True
        user_dir = os.path.join(self.dest_dir, user_hash)
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
            is_new = True
        if is_new:
            if ADMIN_JID and ADMIN_NOTIFY_LEVEL in ('all', 'registrations'):
                self.send_message(mto=ADMIN_JID, mbody=f"🆕 Новый пользователь: {bare_jid} ({user_hash})", mtype='chat')
        return user_dir, user_hash

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

    def handle_presence_subscribe(self, presence):
        jid = presence['from'].bare
        logging.info(f"🆕 Запрос подписки от {jid}")
        if not self.is_allowed(presence['from']):
            logging.info(f"ACCESS DENIED (subscribe) from {jid}")
            self.send_message(mto=jid,
                              mbody=f"⚠️ Доступ запрещён. Пожалуйста, обратитесь к администратору для получения доступа: {ADMIN_JID}",
                              mtype='chat')
            return
        self.send_presence(pto=jid, ptype='subscribed')
        self.send_presence(pto=jid, ptype='subscribe')
        is_admin = ADMIN_JID and jid == ADMIN_JID.lower()
        _, user_hash = self.get_user_info(presence['from'])
        welcome_msg = f"Добро пожаловать!\nЯ бот для быстрой передачи файлов.\n\n{self.get_help_text(is_admin, user_hash)}"
        self.send_message(mto=jid, mbody=welcome_msg, mtype='chat')

    def handle_presence_subscribed(self, presence):
        jid = presence['from'].bare
        logging.info(f"✅ Подписка подтверждена от {jid}")
        if ADMIN_JID:
            self.send_message(mto=ADMIN_JID, mbody=f"✅ Пользователь {jid} добавил бота в контакты", mtype='chat')

    def handle_presence_unsubscribe(self, presence):
        jid = presence['from'].bare
        logging.info(f"➖ Запрос отписки от {jid}")
        if ADMIN_JID:
            self.send_message(mto=ADMIN_JID, mbody=f"➖ Пользователь {jid} удалил бота из контактов", mtype='chat')

    def handle_presence_unsubscribed(self, presence):
        jid = presence['from'].bare
        logging.info(f"❌ Подписка отменена от {jid}")

    def handle_message(self, msg):
        if msg['type'] not in ('chat', 'normal') or not msg['body']:
            return
        if not self.is_allowed(msg['from']):
            logging.info(f"ACCESS DENIED (msg) from {msg['from']}")
            if ADMIN_JID and ADMIN_NOTIFY_LEVEL == 'all':
                self.send_message(mto=ADMIN_JID, mbody=f"🚫 Попытка сообщения от {msg['from']}", mtype='chat')
            self.send_message(mto=msg['from'],
                              mbody=f"⚠️ Доступ запрещён. Пожалуйста, обратитесь к администратору для получения доступа: {ADMIN_JID}",
                              mtype='chat')
            return

        parts = msg['body'].strip().split()
        if not parts: return
        cmd = parts[0].lower()
        user_dir, user_hash = self.get_user_info(msg['from'])
        def reply(text): self.send_message(mto=msg['from'], mbody=text, mtype='chat')
        cmd_executed = False

        if cmd in ('help', '?'):
            if len(parts) == 1:
                cmd_executed = True
                is_admin = ADMIN_JID and msg['from'].bare.lower() == ADMIN_JID.lower()
                used = get_dir_size(user_dir)
                help_text = self.get_help_text(is_admin, user_hash) + f"\n\n📊 Квота: {format_size(used)} / {format_size(QUOTA_LIMIT_BYTES)}"
                reply(help_text)
        elif cmd == 'ping':
            if len(parts) == 1:
                cmd_executed = True
                reply("pong")
        elif cmd == 'mkdir':
            if len(parts) == 2:
                cmd_executed = True
                target = get_safe_path(user_dir, parts[1])
                if target:
                    rel = os.path.relpath(target, user_dir)
                    if rel != "." and rel.count(os.sep) >= MAX_DIR_DEPTH:
                        reply(f"❌ Ошибка: Максимальная глубина вложенности — {MAX_DIR_DEPTH} уровня")
                    else:
                        try:
                            os.makedirs(target, exist_ok=True)
                            reply(f"📁 Директория создана: {rel}")
                        except Exception as e:
                            reply(f"❌ Ошибка: {e}")
                else: reply("❌ Недопустимый путь")
        elif cmd == 'rmdir':
            if len(parts) == 2:
                cmd_executed = True
                items = get_all_items(user_dir)
                resolved_paths = resolve_items_list(user_dir, parts[1], items)
                removed_count = 0
                for target in resolved_paths:
                    if target and os.path.isdir(target):
                        try:
                            os.rmdir(target)
                            removed_count += 1
                        except Exception: pass
                if removed_count: reply(f"🗑 Удалено директорий: {removed_count}")
                else: reply("❌ Директории не найдены или не пусты")
        elif cmd == 'mv':
            if len(parts) == 3:
                cmd_executed = True
                items = get_all_items(user_dir)
                dst = resolve_item(user_dir, parts[2], items)
                if not dst: reply("❌ Недопустимый путь назначения")
                else:
                    resolved_srcs = resolve_items_list(user_dir, parts[1], items)
                    if not resolved_srcs: reply("❌ Объекты для перемещения не найдены")
                    elif len(resolved_srcs) > 1:
                        if not os.path.isdir(dst): reply("❌ При перемещении нескольких объектов назначение должно быть директорией")
                        else:
                            moved_count = 0
                            for src in resolved_srcs:
                                if os.path.abspath(src) == os.path.abspath(dst): continue
                                new_dst = os.path.join(dst, os.path.basename(src.rstrip('/')))
                                rel_dst = os.path.relpath(new_dst, user_dir)
                                is_dir = os.path.isdir(src)
                                limit = MAX_DIR_DEPTH if not is_dir else MAX_DIR_DEPTH - 1
                                if rel_dst != "." and rel_dst.count(os.sep) > limit: continue
                                try:
                                    new_dst = get_unique_path(new_dst)
                                    os.rename(src, new_dst)
                                    moved_count += 1
                                except Exception: pass
                            reply(f"🚚 Перемещено объектов: {moved_count}")
                    else:
                        src = resolved_srcs[0]
                        if src and os.path.exists(src):
                            try:
                                final_dst = dst
                                if os.path.isdir(dst): final_dst = os.path.join(dst, os.path.basename(src.rstrip('/')))
                                rel_dst = os.path.relpath(final_dst, user_dir)
                                is_dir = os.path.isdir(src)
                                limit = MAX_DIR_DEPTH if not is_dir else MAX_DIR_DEPTH - 1
                                if rel_dst != "." and rel_dst.count(os.sep) > limit: reply(f"❌ Ошибка: Превышена максимальная глубина вложенности")
                                else:
                                    final_dst = get_unique_path(final_dst)
                                    os.rename(src, final_dst)
                                    reply(f"🚚 Перемещено: {os.path.relpath(src, user_dir)} -> {os.path.relpath(final_dst, user_dir)}")
                            except Exception as e: reply(f"❌ Ошибка: {e}")
                        else: reply("❌ Файл не найден")
        elif cmd in ('ls', 'lss', 'lsl'):
            if len(parts) <= 2:
                mode = 'links'
                if cmd == 'lss': mode = 'size'
                elif cmd == 'lsl': mode = 'long'
                elif len(parts) == 2:
                    if parts[1] == '-s': mode = 'size'
                    elif parts[1] == '-l': mode = 'long'
                    else: mode = None
                if mode:
                    cmd_executed = True
                    items = get_all_items(user_dir)
                    if not items: reply("📁 Папка пуста")
                    else:
                        res = []
                        for i, itm in enumerate(items):
                            depth = itm.count('/')
                            if itm.endswith('/'): depth -= 1
                            name = os.path.basename(itm.rstrip('/'))
                            if itm.endswith('/'): name += "/"
                            display_itm = ("    " * depth + "└── " + name) if depth > 0 else name
                            full_path = os.path.join(user_dir, itm)
                            if mode == 'links': res.append(f"{i+1} - {display_itm}")
                            elif mode == 'size':
                                if itm.endswith('/'): res.append(f"{i+1} - {display_itm} [директория]")
                                else: res.append(f"{i+1} - {display_itm} [{format_size(os.path.getsize(full_path))}]")
                            elif mode == 'long':
                                st = os.stat(full_path)
                                size, mtime = format_size(st.st_size), datetime.datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M')
                                if itm.endswith('/'): res.append(f"{i+1} - {display_itm} (директория, {mtime})")
                                else: res.append(f"{i+1} - {display_itm} ({size}, загружен {mtime})")
                        reply("\n" + "\n".join(res))
        elif cmd in ('link', 'lnk'):
            if len(parts) == 2:
                cmd_executed = True
                items = get_all_items(user_dir)
                if not items: reply("📁 Папка пуста")
                elif parts[1] == '*':
                    res = [f"{i+1} - {self.base_url}/{user_hash}/{safe_quote(itm)}" for i, itm in enumerate(items) if not itm.endswith('/')]
                    reply("\n".join(res))
                else:
                    resolved_paths = resolve_items_list(user_dir, parts[1], items)
                    res = []
                    for path in resolved_paths:
                        if not os.path.isdir(path):
                            rel = os.path.relpath(path, user_dir)
                            try: idx = items.index(rel)
                            except ValueError: idx = -1
                            res.append(f"{idx+1 if idx >=0 else '?'} - {self.base_url}/{user_hash}/{safe_quote(rel)}")
                    if res: reply("\n".join(res))
        elif cmd == 'rm':
            if 2 <= len(parts) <= 3:
                cmd_executed = True
                items = get_all_items(user_dir)
                if not items: reply("📁 Папка пуста")
                elif parts[1] == '*':
                    if len(parts) == 3 and parts[2].lower() == 'confirm':
                        for item in os.listdir(user_dir):
                            item_path = os.path.join(user_dir, item)
                            try:
                                if os.path.isdir(item_path): shutil.rmtree(item_path)
                                else: os.remove(item_path)
                            except Exception: pass
                        reply("🗑 Все файлы и папки удалены.")
                    else: reply("⚠ Чтобы удалить ВСЕ файлы, напишите: rm * confirm")
                else:
                    if len(parts) == 2:
                        resolved_paths = resolve_items_list(user_dir, parts[1], items)
                        removed_count = 0
                        for path in resolved_paths:
                            try:
                                if os.path.isdir(path): shutil.rmtree(path)
                                else: os.remove(path)
                                removed_count += 1
                            except Exception: pass
                        if removed_count: reply(f"🗑 Удалено объектов: {removed_count}")
        elif cmd == 'priv':
            if len(parts) == 1:
                cmd_executed = True
                index_path = os.path.join(user_dir, 'index.html')
                if not os.path.exists(index_path):
                    with open(index_path, 'w') as f: f.write("<html><body><h1>Private Archive</h1></body></html>")
                    reply("🔒 Архив теперь приватный (создан index.html)")
                else: reply("ℹ Архив уже приватный.")
        elif cmd == 'pub':
            if len(parts) == 1:
                cmd_executed = True
                index_path = os.path.join(user_dir, 'index.html')
                if os.path.exists(index_path): os.remove(index_path); reply("🔓 Архив теперь публичный (удалён index.html)")
                else: reply("ℹ Архив уже публичный.")

        if not cmd_executed and ADMIN_JID and msg['from'].bare.lower() == ADMIN_JID.lower():
            if cmd == 'add' and len(parts) == 2:
                cmd_executed = True
                entries = [e.strip().lower() for e in parts[1].split(',') if e.strip()]
                added = []
                for entry in entries:
                    if entry == '*' or '@' in entry or '.' in entry:
                        self.db.add_to_whitelist(entry); added.append(entry)
                if added:
                    if '*' in added: reply("🌟 Доступ разрешён для ВСЕХ пользователей.")
                    else: reply(f"➕ Добавлено в белый список: {', '.join(added)}")
                else: reply("⚠ Неверный формат. Используйте user@domain, domain или *")
            elif cmd == 'del' and len(parts) == 2:
                cmd_executed = True
                entries, whitelist = [e.strip().lower() for e in parts[1].split(',') if e.strip()], self.db.get_whitelist()
                removed = [e for e in entries if e in whitelist]
                for e in removed: self.db.remove_from_whitelist(e)
                if removed: reply(f"➖ Удалено из белого списка: {', '.join(removed)}")
                else: reply("❓ Ничего не найдено для удаления из белого списка.")
            elif cmd == 'block' and len(parts) == 2:
                cmd_executed = True
                entries = [e.strip().lower() for e in parts[1].split(',') if e.strip()]
                added = [e for e in entries if '@' in e or '.' in e]
                for e in added: self.db.add_to_blacklist(e)
                if added: reply(f"🚫 Добавлено в чёрный список: {', '.join(added)}")
                else: reply("⚠ Неверный формат. Используйте user@domain или domain")
            elif cmd == 'unblock' and len(parts) == 2:
                cmd_executed = True
                entries, blacklist = [e.strip().lower() for e in parts[1].split(',') if e.strip()], self.db.get_blacklist()
                removed = [e for e in entries if e in blacklist]
                for e in removed: self.db.remove_from_blacklist(e)
                if removed: reply(f"✅ Удалено из чёрного списка: {', '.join(removed)}")
                else: reply("❓ Ничего не найдено для удаления из чёрного списка.")
            elif cmd == 'list' and len(parts) == 1:
                cmd_executed = True
                res_w, res_b = "\n".join(sorted(self.db.get_whitelist())), "\n".join(sorted(self.db.get_blacklist()))
                reply(f"📄 Белый список:\n{res_w or '(пусто)'}\n\n🚫 Чёрный список:\n{res_b or '(пусто)'}")

        if not cmd_executed:
            is_admin = ADMIN_JID and msg['from'].bare.lower() == ADMIN_JID.lower()
            used = get_dir_size(user_dir)
            reply(self.get_help_text(is_admin, user_hash) + f"\n\n📊 Квота: {format_size(used)} / {format_size(QUOTA_LIMIT_BYTES)}")

    def handle_raw_si(self, iq):
        if not self.is_allowed(iq['from']):
            logging.info(f"ACCESS DENIED (SI) from {iq['from']}")
            if ADMIN_JID and ADMIN_NOTIFY_LEVEL == 'all':
                self.send_message(mto=ADMIN_JID, mbody=f"🚫 Попытка передачи файла от {iq['from']}", mtype='chat')
            self.send_message(mto=iq['from'], mbody=f"⚠️ Доступ запрещён. Пожалуйста, обратитесь к администратору для получения доступа: {ADMIN_JID}", mtype='chat')
            reply = iq.reply(); reply['type'] = 'error'; return reply.send()
        try:
            si = iq.xml.find('{http://jabber.org/protocol/si}si')
            sid, tag = si.get('id'), si.find('{http://jabber.org/protocol/si/profile/file-transfer}file')
            fname, fsize = os.path.basename(tag.get('name')).replace(' ', '_'), int(tag.get('size', 0))
            logging.info(f"SI REQUEST: {fname} ({fsize} bytes) from {iq['from']}, sid={sid}")
            user_dir, _ = self.get_user_info(iq['from'])
            if get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                logging.info(f"QUOTA EXCEEDED for {iq['from']}"); self.send_message(mto=iq['from'], mbody="⚠ Квота превышена!", mtype='chat')
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
        reply = iq.reply(); reply.append(ET.Element('{urn:xmpp:ping}ping')); reply.send()
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
        path = os.path.join(user_dir, os.path.basename(file_info['name']))
        received = 0
        try:
            with open(path, 'wb') as f:
                while received < file_info['size']:
                    chunk = await reader.read(min(file_info['size'] - received, 1048576))
                    if not chunk: break
                    f.write(chunk); received += len(chunk)
                f.flush(); os.fsync(f.fileno())
            if received == file_info['size']:
                self.send_message(mto=peer_jid, mbody=f"✅ Готово!\n{self.base_url}/{user_hash}/{safe_quote(file_info['name'])}", mtype='chat')
            else:
                if os.path.exists(path): os.remove(path)
        except Exception as e:
            logging.error(f"Ошибка при приёме файла: {e}")
            if os.path.exists(path): os.remove(path)
