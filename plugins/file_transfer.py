import os
import hashlib
import asyncio
import logging
from slixmpp.xmlstream import ET, matcher, handler
from config import ADMIN_JID, ADMIN_NOTIFY_LEVEL, QUOTA_LIMIT_BYTES
from utils import get_dir_size, safe_quote
from .base import BasePlugin

class FileTransferPlugin(BasePlugin):
    def __init__(self, bot):
        super().__init__(bot)
        self.bot.register_handler(
            handler.Callback('SI', matcher.MatchXPath('{jabber:client}iq/{http://jabber.org/protocol/si}si'), self.handle_raw_si)
        )
        self.bot.register_handler(
            handler.Callback('S5B', matcher.MatchXPath('{jabber:client}iq/{http://jabber.org/protocol/bytestreams}query'), self.handle_raw_s5b)
        )
        self.bot.add_event_handler("ibb_stream_start", self.handle_ibb_stream)

    def handle_raw_si(self, iq):
        if not self.bot.is_allowed(iq['from']):
            logging.info(f"ACCESS DENIED (SI) from {iq['from']}")
            if ADMIN_JID and ADMIN_NOTIFY_LEVEL == 'all':
                self.bot.send_message(mto=ADMIN_JID, mbody=f"🚫 Попытка передачи файла от {iq['from']}", mtype='chat')
            self.bot.send_message(mto=iq['from'], mbody=f"⚠️ Доступ запрещён. Пожалуйста, обратитесь к администратору для получения доступа: {ADMIN_JID}", mtype='chat')
            reply = iq.reply(); reply['type'] = 'error'; return reply.send()
        try:
            si = iq.xml.find('{http://jabber.org/protocol/si}si')
            sid, tag = si.get('id'), si.find('{http://jabber.org/protocol/si/profile/file-transfer}file')
            fname, fsize = os.path.basename(tag.get('name')).replace(' ', '_'), int(tag.get('size', 0))
            logging.info(f"SI REQUEST: {fname} ({fsize} bytes) from {iq['from']}, sid={sid}")

            user_dir, _ = self.bot.get_user_info(iq['from'])
            if get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                logging.info(f"QUOTA EXCEEDED for {iq['from']}"); self.bot.send_message(mto=iq['from'], mbody="⚠ Квота превышена!", mtype='chat')
                reply = iq.reply(); reply['type'] = 'error'; return reply.send()

            # Parse stream methods
            feature_neg = si.find('{http://jabber.org/protocol/feature-neg}feature')
            offered_methods = []
            if feature_neg is not None:
                x_data = feature_neg.find('{jabber:x:data}x')
                if x_data is not None:
                    field = x_data.find('{jabber:x:data}field[@var="stream-method"]')
                    if field is not None:
                        # Extract from <value> and <option><value>
                        offered_methods = [v.text for v in field.findall('{jabber:x:data}value')]
                        offered_methods.extend([v.text for v in field.findall('{jabber:x:data}option/{jabber:x:data}value')])

            chosen_method = None
            if 'http://jabber.org/protocol/bytestreams' in offered_methods:
                chosen_method = 'http://jabber.org/protocol/bytestreams'
            elif 'http://jabber.org/protocol/ibb' in offered_methods:
                chosen_method = 'http://jabber.org/protocol/ibb'

            if not chosen_method:
                logging.warning(f"No supported stream method offered by {iq['from']}")
                reply = iq.reply(); reply['type'] = 'error'; return reply.send()

            self.bot.pending_files[sid] = {
                'name': fname,
                'size': fsize,
                'timestamp': asyncio.get_event_loop().time(),
                'ibb_allowed': 'http://jabber.org/protocol/ibb' in offered_methods,
                'peer_jid': iq['from']
            }

            reply = iq.reply()
            res_si = ET.Element('{http://jabber.org/protocol/si}si', {'id': sid})
            feature = ET.SubElement(res_si, '{http://jabber.org/protocol/feature-neg}feature')
            x = ET.SubElement(feature, '{jabber:x:data}x', type='submit')
            field = ET.SubElement(x, '{jabber:x:data}field', var='stream-method')
            ET.SubElement(field, '{jabber:x:data}value').text = chosen_method
            reply.append(res_si); reply.send()
        except Exception as e: logging.error(f"SI ERROR: {e}")

    def handle_raw_s5b(self, iq):
        logging.info(f"S5B REQUEST from {iq['from']}")
        asyncio.create_task(self._manual_socks5_connect(iq))

    async def _manual_socks5_connect(self, iq):
        sid = None
        try:
            query = iq.xml.find('{http://jabber.org/protocol/bytestreams}query')
            if query is None: return
            sid = query.get('sid')
            file_info = self.bot.pending_files.get(sid)
            if not file_info: return
            dst_addr = hashlib.sha1(f"{sid}{iq['from'].full}{self.bot.boundjid.full}".encode()).hexdigest()
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
                    await self.download_file_task(reader, file_info, iq['from'], sid)
                    writer.close(); await writer.wait_closed(); return
                except Exception: continue

            # If we are here, all hosts failed
            reply = iq.reply(); reply['type'] = 'error'; reply.send()

            # If IBB was not an option, we should cleanup now.
            if not file_info.get('ibb_allowed'):
                if sid in self.bot.pending_files:
                    del self.bot.pending_files[sid]
        except Exception as e:
            logging.error(f"SOCKS5 ERROR: {e}")

    def handle_ibb_stream(self, stream):
        sid = stream.sid
        file_info = self.bot.pending_files.get(sid)
        if file_info:
            # Verify JID match
            if file_info['peer_jid'].bare != stream.peer_jid.bare:
                logging.warning(f"JID mismatch for IBB stream {sid}: {file_info['peer_jid']} != {stream.peer_jid}")
                stream.close()
                return

            logging.info(f"IBB stream started for sid={sid}")
            asyncio.create_task(self.download_file_task(stream, file_info, stream.peer_jid, sid))
        else:
            logging.warning(f"Unknown IBB stream sid={sid}")
            stream.close()

    async def download_file_task(self, reader, file_info, peer_jid, sid):
        user_dir, user_hash = self.bot.get_user_info(peer_jid)
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
                self.bot.send_message(mto=peer_jid, mbody=f"✅ Готово!\n{self.bot.base_url}/{user_hash}/{safe_quote(file_info['name'])}", mtype='chat')
            else:
                if os.path.exists(path): os.remove(path)
        except Exception as e:
            logging.error(f"Ошибка при приёме файла: {e}")
            if os.path.exists(path): os.remove(path)
        finally:
            if sid in self.bot.pending_files:
                del self.bot.pending_files[sid]
