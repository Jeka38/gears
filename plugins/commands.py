import os
import shutil
import datetime
import urllib.parse
import asyncio
from config import ADMIN_JID, QUOTA_LIMIT_BYTES, MAX_DIR_DEPTH
from utils import (
    get_dir_size, format_size, get_safe_path, get_all_items,
    resolve_items_list, resolve_item, get_unique_path, safe_quote
)
from .base import BasePlugin

class CommandsPlugin(BasePlugin):
    def __init__(self, bot):
        super().__init__(bot)
        self.bot.add_event_handler("message", self.handle_message)

    def handle_message(self, msg):
        if msg['type'] not in ('chat', 'normal'):
            return

        # Handle XEP-0066 Out-of-Band Data in messages
        oob = msg.xml.find('{jabber:x:oob}x')
        if oob is not None:
            url = oob.find('{jabber:x:oob}url')
            if url is not None and url.text:
                desc = oob.find('{jabber:x:oob}desc')
                fname = desc.text if desc is not None and desc.text else os.path.basename(url.text)
                import asyncio
                asyncio.create_task(self.bot.file_transfer.download_from_url(url.text, fname, msg['from']))
                return

        if not msg['body']:
            return
        if not self.bot.is_allowed(msg['from']):
            self.reply(msg, f"⚠️ Доступ запрещён. Пожалуйста, обратитесь к администратору для получения доступа: {ADMIN_JID}")
            return

        parts = msg['body'].strip().split()
        if not parts: return

        # Detect and handle direct URLs in message body (HTTP Upload style)
        if len(parts) == 1 and parts[0].lower().startswith(('http://', 'https://')):
            url = parts[0]
            fname = os.path.basename(urllib.parse.urlparse(url).path) or "downloaded_file"
            self.bot.loop.create_task(self.bot.file_transfer.download_from_url(url, fname, msg['from']))
            return

        cmd = parts[0].lower()
        user_dir, user_hash = self.bot.get_user_info(msg['from'])
        cmd_executed = False

        # User commands
        if cmd in ('help', '?') and len(parts) == 1:
            cmd_executed = True
            is_admin = ADMIN_JID and msg['from'].bare.lower() == ADMIN_JID.lower()
            used = get_dir_size(user_dir)
            self.reply(msg, self.bot.get_help_text(is_admin, user_hash) + f"\n\n📊 Квота: {format_size(used)} / {format_size(QUOTA_LIMIT_BYTES)}")
        elif cmd == 'ping' and len(parts) == 1:
            cmd_executed = True
            self.reply(msg, "pong")
        elif cmd == 'mkdir' and len(parts) == 2:
            cmd_executed = True
            target = get_safe_path(user_dir, parts[1])
            if target:
                rel = os.path.relpath(target, user_dir)
                if rel != "." and rel.count(os.sep) >= MAX_DIR_DEPTH:
                    self.reply(msg, f"❌ Ошибка: Максимальная глубина вложенности — {MAX_DIR_DEPTH} уровня")
                else:
                    try: os.makedirs(target, exist_ok=True); self.reply(msg, f"📁 Директория создана: {rel}")
                    except Exception as e: self.reply(msg, f"❌ Ошибка: {e}")
            else: self.reply(msg, "❌ Недопустимый путь")
        elif cmd == 'rmdir' and len(parts) == 2:
            cmd_executed = True
            items = get_all_items(user_dir)
            resolved_paths = resolve_items_list(user_dir, parts[1], items)
            removed_count = 0
            for target in resolved_paths:
                if target and os.path.isdir(target):
                    try: os.rmdir(target); removed_count += 1
                    except Exception: pass
            if removed_count: self.reply(msg, f"🗑 Удалено директорий: {removed_count}")
            else: self.reply(msg, "❌ Директории не найдены или не пусты")
        elif cmd == 'mv' and len(parts) == 3:
            cmd_executed = True
            items = get_all_items(user_dir)
            dst = resolve_item(user_dir, parts[2], items)
            if not dst: self.reply(msg, "❌ Недопустимый путь назначения")
            else:
                resolved_srcs = resolve_items_list(user_dir, parts[1], items)
                if not resolved_srcs: self.reply(msg, "❌ Объекты для перемещения не найдены")
                elif len(resolved_srcs) > 1:
                    if not os.path.isdir(dst): self.reply(msg, "❌ При перемещении нескольких объектов назначение должно быть директорией")
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
                                os.rename(src, new_dst); moved_count += 1
                            except Exception: pass
                        self.reply(msg, f"🚚 Перемещено объектов: {moved_count}")
                else:
                    src = resolved_srcs[0]
                    if src and os.path.exists(src):
                        try:
                            final_dst = dst
                            if os.path.isdir(dst):
                                final_dst = os.path.join(dst, os.path.basename(src.rstrip('/')))
                            else:
                                # Если это не директория, то это переименование.
                                if os.path.isfile(src):
                                    # Сохраняем расширение исходного файла.
                                    _, ext = os.path.splitext(src)
                                    final_dst_base, _ = os.path.splitext(final_dst)
                                    final_dst = final_dst_base + ext

                            rel_dst = os.path.relpath(final_dst, user_dir)
                            is_dir = os.path.isdir(src)
                            limit = MAX_DIR_DEPTH if not is_dir else MAX_DIR_DEPTH - 1
                            if rel_dst != "." and rel_dst.count(os.sep) > limit: self.reply(msg, f"❌ Ошибка: Превышена максимальная глубина вложенности")
                            else:
                                final_dst = get_unique_path(final_dst)
                                os.rename(src, final_dst)
                                self.reply(msg, f"🚚 Перемещено: {os.path.relpath(src, user_dir)} -> {os.path.relpath(final_dst, user_dir)}")
                        except Exception as e: self.reply(msg, f"❌ Ошибка: {e}")
                    else: self.reply(msg, "❌ Файл не найден")
        elif cmd in ('ls', 'lss', 'lsl') and len(parts) <= 2:
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
                if not items:
                    if mode == 'size':
                        used = get_dir_size(user_dir)
                        self.reply(msg, f"📁 Папка пуста\n\n📊 Квота: {format_size(used)} / {format_size(QUOTA_LIMIT_BYTES)}")
                    else:
                        self.reply(msg, "📁 Папка пуста")
                else:
                    res = ["Список файлов:"]
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
                    if mode == 'size':
                        used = get_dir_size(user_dir)
                        res.append(f"\n📊 Квота: {format_size(used)} / {format_size(QUOTA_LIMIT_BYTES)}")
                    self.reply(msg, "\n".join(res))
        elif cmd in ('link', 'lnk') and len(parts) == 2:
            cmd_executed = True
            items = get_all_items(user_dir)
            if not items: self.reply(msg, "📁 Папка пуста")
            elif parts[1] == '*':
                res = [f"{i+1} - {self.bot.base_url}/{user_hash}/{safe_quote(itm)}" for i, itm in enumerate(items) if not itm.endswith('/')]
                self.reply(msg, "\n".join(res))
            else:
                resolved_paths = resolve_items_list(user_dir, parts[1], items)
                res = []
                for path in resolved_paths:
                    if not os.path.isdir(path):
                        rel = os.path.relpath(path, user_dir)
                        try: idx = items.index(rel)
                        except ValueError: idx = -1
                        res.append(f"{idx+1 if idx >=0 else '?'} - {self.bot.base_url}/{user_hash}/{safe_quote(rel)}")
                if res: self.reply(msg, "\n".join(res))
        elif cmd == 'rm' and 2 <= len(parts) <= 3:
            cmd_executed = True
            items = get_all_items(user_dir)
            if not items: self.reply(msg, "📁 Папка пуста")
            elif parts[1] == '*':
                if len(parts) == 3 and parts[2].lower() == 'confirm':
                    for item in os.listdir(user_dir):
                        item_path = os.path.join(user_dir, item)
                        try:
                            if os.path.isdir(item_path): shutil.rmtree(item_path)
                            else: os.remove(item_path)
                        except Exception: pass
                    self.reply(msg, "🗑 Все файлы и папки удалены.")
                else: self.reply(msg, "⚠ Чтобы удалить ВСЕ файлы, напишите: rm * confirm")
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
                    if removed_count: self.reply(msg, f"🗑 Удалено объектов: {removed_count}")
        elif cmd == 'priv' and len(parts) == 1:
            cmd_executed = True
            index_path = os.path.join(user_dir, 'index.html')
            if not os.path.exists(index_path):
                php_path = os.path.join(user_dir, 'index.php')
                if os.path.exists(php_path): os.remove(php_path)
                with open(index_path, 'w') as f: f.write("<html><body><h1>Private Archive</h1></body></html>")
                self.reply(msg, "🔒 Архив теперь приватный (создан index.html, index.php удалён)")
            else: self.reply(msg, "ℹ Архив уже приватный.")
        elif cmd == 'pub' and len(parts) == 1:
            cmd_executed = True
            index_path = os.path.join(user_dir, 'index.html')
            php_path = os.path.join(user_dir, 'index.php')
            if os.path.exists(index_path) or os.path.exists(php_path):
                if os.path.exists(index_path): os.remove(index_path)
                if os.path.exists(php_path): os.remove(php_path)
                self.reply(msg, "🔓 Архив теперь публичный (удалены index.html и index.php)")
            else: self.reply(msg, "ℹ Архив уже публичный.")
        elif cmd == 'album' and len(parts) == 1:
            cmd_executed = True
            php_path = os.path.join(user_dir, 'index.php')
            if not os.path.exists(php_path):
                try:
                    os.chmod(user_dir, 0o777)
                    shutil.copy('index.php', php_path)
                    self.reply(msg, "🖼 Режим альбома активирован (создан index.php)")
                except Exception as e: self.reply(msg, f"❌ Ошибка при создании альбома: {e}")
            else: self.reply(msg, "ℹ Режим альбома уже активен.")

        # Admin commands
        if not cmd_executed and ADMIN_JID and msg['from'].bare.lower() == ADMIN_JID.lower():
            if cmd == 'add' and len(parts) == 2:
                cmd_executed = True
                entries = [e.strip().lower() for e in parts[1].split(',') if e.strip()]
                added = []
                for entry in entries:
                    if entry == '*' or '@' in entry or '.' in entry:
                        self.db.add_to_whitelist(entry); added.append(entry)
                if added:
                    if '*' in added: self.reply(msg, "🌟 Доступ разрешён для ВСЕХ пользователей.")
                    else: self.reply(msg, f"➕ Добавлено в белый список: {', '.join(added)}")
                else: self.reply(msg, "⚠ Неверный формат. Используйте user@domain, domain или *")
            elif cmd == 'del' and len(parts) == 2:
                cmd_executed = True
                entries, whitelist = [e.strip().lower() for e in parts[1].split(',') if e.strip()], self.db.get_whitelist()
                removed = [e for e in entries if e in whitelist]
                for e in removed: self.db.remove_from_whitelist(e)
                if removed: self.reply(msg, f"➖ Удалено из белого списка: {', '.join(removed)}")
                else: self.reply(msg, "❓ Ничего не найдено для удаления из белого списка.")
            elif cmd == 'block' and len(parts) == 2:
                cmd_executed = True
                entries = [e.strip().lower() for e in parts[1].split(',') if e.strip()]
                added = [e for e in entries if '@' in e or '.' in e]
                for e in added: self.db.add_to_blacklist(e)
                if added: self.reply(msg, f"🚫 Добавлено в чёрный список: {', '.join(added)}")
                else: self.reply(msg, "⚠ Неверный формат. Используйте user@domain или domain")
            elif cmd == 'unblock' and len(parts) == 2:
                cmd_executed = True
                entries, blacklist = [e.strip().lower() for e in parts[1].split(',') if e.strip()], self.db.get_blacklist()
                removed = [e for e in entries if e in blacklist]
                for e in removed: self.db.remove_from_blacklist(e)
                if removed: self.reply(msg, f"✅ Удалено из чёрного списка: {', '.join(removed)}")
                else: self.reply(msg, "❓ Ничего не найдено для удаления из чёрного списка.")
            elif cmd == 'list' and len(parts) == 1:
                cmd_executed = True
                res_w, res_b = "\n".join(sorted(self.db.get_whitelist())), "\n".join(sorted(self.db.get_blacklist()))
                self.reply(msg, f"📄 Белый список:\n{res_w or '(пусто)'}\n\n🚫 Чёрный список:\n{res_b or '(пусто)'}")

        if not cmd_executed:
            is_admin = ADMIN_JID and msg['from'].bare.lower() == ADMIN_JID.lower()
            used = get_dir_size(user_dir)
            self.reply(msg, self.bot.get_help_text(is_admin, user_hash) + f"\n\n📊 Квота: {format_size(used)} / {format_size(QUOTA_LIMIT_BYTES)}")
