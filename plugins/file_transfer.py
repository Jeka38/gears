import os
import socket
import hashlib
import asyncio
import logging
import aiohttp
from slixmpp.xmlstream import ET, matcher, handler
from config import ADMIN_JID, ADMIN_NOTIFY_LEVEL, QUOTA_LIMIT_BYTES
from utils import get_dir_size, safe_quote, get_unique_path
from .base import BasePlugin

class FileTransferPlugin(BasePlugin):
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except: return '127.0.0.1'

    KNOWN_PROXIES = {
        'proxy.eu.jabber.network': {'host': 'proxy.eu.jabber.network', 'port': 1080},
        'proxy.jabber.ru': {'host': 'proxy.jabber.ru', 'port': 1080},
        'proxy.jabbim.cz': {'host': 'proxy.jabbim.cz', 'port': 1080},
        'proxy.yax.im': {'host': 'proxy.yax.im', 'port': 1080},
    }

    def is_php(self, *names):
        for name in names:
            if name and isinstance(name, str) and name.lower().endswith('.php'):
                return True
        return False

    def __init__(self, bot):
        super().__init__(bot)
        self.bot.register_handler(
            handler.Callback('SI', matcher.MatchXPath('{jabber:client}iq/{http://jabber.org/protocol/si}si'), self.handle_raw_si)
        )
        self.bot.register_handler(
            handler.Callback('S5B', matcher.MatchXPath('{jabber:client}iq/{http://jabber.org/protocol/bytestreams}query'), self.handle_raw_s5b)
        )
        self.bot.register_handler(
            handler.Callback('Jingle', matcher.MatchXPath('{jabber:client}iq/{urn:xmpp:jingle:1}jingle'), self.handle_jingle)
        )
        self.bot.register_handler(
            handler.Callback('OOB', matcher.MatchXPath('{jabber:client}iq/{jabber:iq:oob}query'), self.handle_iq_oob)
        )
        self.bot.add_event_handler("ibb_stream_start", self.handle_ibb_stream)

    def handle_iq_oob(self, iq):
        logging.info(f"IQ OOB REQUEST from {iq['from']}:\n{ET.tostring(iq.xml, encoding='unicode')}")
        query = iq.xml.find('{jabber:iq:oob}query')
        if query is None: return
        url_tag = query.find('{jabber:iq:oob}url')
        if url_tag is None or not url_tag.text: return
        url = url_tag.text
        desc = query.find('{jabber:iq:oob}desc')
        fname = desc.text if desc is not None and desc.text else os.path.basename(url)

        # Immediate PHP check for OOB
        import urllib.parse
        path_name = os.path.basename(urllib.parse.urlparse(url).path)
        if self.is_php(fname, path_name):
            self.bot.send_message(mto=iq['from'], mbody="❌ Ошибка: Загрузка PHP-файлов запрещена!", mtype='chat')
            reply = iq.error()
            reply['error']['condition'] = 'not-acceptable'
            reply.send()
            return

        self.bot.pending_files[f"oob_{url}"] = asyncio.create_task(self.download_from_url(url, fname, iq['from']))
        iq.reply().send()

    async def download_from_url(self, url, fname, peer_jid):
        logging.info(f"Downloading OOB from {url}")
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        path_name = os.path.basename(parsed.path)
        if self.is_php(fname, path_name):
            self.bot.send_message(mto=peer_jid, mbody="❌ Ошибка: Загрузка PHP-файлов запрещена!", mtype='chat')
            return
        user_dir, user_hash = self.bot.get_user_info(peer_jid)
        fname = os.path.basename(fname).replace(' ', '_')
        path = get_unique_path(os.path.join(user_dir, fname))
        loop = asyncio.get_event_loop()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=300) as resp:
                    if resp.status == 200:
                        fsize = int(resp.headers.get('Content-Length', 0))
                        if fsize > 0 and get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                             self.bot.send_message(mto=peer_jid, mbody="⚠ Квота превышена!", mtype='chat'); return
                        with open(path, 'wb') as f:
                            async for chunk in resp.content.iter_chunked(1048576):
                                await loop.run_in_executor(None, f.write, chunk)
                            await loop.run_in_executor(None, f.flush); await loop.run_in_executor(None, os.fsync, f.fileno())
                        real_fname = os.path.basename(path)
                        self.bot.send_message(mto=peer_jid, mbody=f"✅ Готово!\n{self.bot.base_url}/{user_hash}/{safe_quote(real_fname)}", mtype='chat')
                    else: logging.error(f"OOB download failed: HTTP {resp.status}")
        except Exception as e:
            logging.error(f"OOB download error: {e}")
            if os.path.exists(path): os.remove(path)

    def handle_jingle(self, iq):
        jingle = iq.xml.find('{urn:xmpp:jingle:1}jingle')
        if jingle is None: return
        action, sid = jingle.get('action'), jingle.get('sid')
        logging.info(f"JINGLE REQUEST ({action}) from {iq['from']}")
        if action == 'session-initiate':
            if not self.bot.is_allowed(iq['from']):
                reply = iq.error()
                reply['error']['condition'] = 'not-authorized'
                reply.send(); return
            content = jingle.find('{urn:xmpp:jingle:1}content')
            if content is None: return
            ft_ns = 'urn:xmpp:jingle:apps:file-transfer:5'
            description = content.find(f'{{{ft_ns}}}description')
            if description is None:
                ft_ns = 'urn:xmpp:jingle:apps:file-transfer:4'; description = content.find(f'{{{ft_ns}}}description')
            if description is None: return
            file_tag = description.find(f'{{{ft_ns}}}file')
            if file_tag is None: return
            name_tag, size_tag = file_tag.find(f'{{{ft_ns}}}name'), file_tag.find(f'{{{ft_ns}}}size')
            if name_tag is None or size_tag is None: return
            if self.is_php(name_tag.text):
                self.bot.send_message(mto=iq['from'], mbody="❌ Ошибка: Загрузка PHP-файлов запрещена!", mtype='chat')
                reply = iq.error()
                reply['error']['condition'] = 'not-acceptable'
                reply.send(); return
            fname, transport_sid = os.path.basename(name_tag.text).replace(' ', '_'), sid
            try: fsize = int(size_tag.text)
            except: fsize = 0
            user_dir, _ = self.bot.get_user_info(iq['from'])
            if get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                reply = iq.error()
                reply['error']['condition'] = 'resource-constraint'
                reply.send(); return
            ibb_t, s5b_t = content.find('{urn:xmpp:jingle:transports:ibb:1}transport'), content.find('{urn:xmpp:jingle:transports:s5b:1}transport')
            if s5b_t is not None and s5b_t.get('sid'): transport_sid = s5b_t.get('sid')
            elif ibb_t is not None and ibb_t.get('sid'): transport_sid = ibb_t.get('sid')
            else: transport_sid = sid
            self.bot.pending_files[sid] = {
                'name': fname, 'size': fsize, 'timestamp': asyncio.get_event_loop().time(),
                'peer_jid': iq['from'], 'ibb_allowed': True,
                'content_name': content.get('name'), 'content_creator': content.get('creator'),
                'ft_ns': ft_ns, 'transport_sid': transport_sid, 's5b_connecting': False
            }
            if transport_sid != sid: self.bot.pending_files[transport_sid] = self.bot.pending_files[sid]
            iq.reply().send()
            try:
                accept_iq = self.bot.make_iq_set(ito=iq['from'])
                res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {'action': 'session-accept', 'sid': sid, 'initiator': iq['from'].full})
                res_c = ET.SubElement(res_j, '{urn:xmpp:jingle:1}content', {'creator': content.get('creator'), 'name': content.get('name')})
                res_d = ET.SubElement(res_c, f'{{{ft_ns}}}description')
                res_f = ET.SubElement(res_d, f'{{{ft_ns}}}file')
                ET.SubElement(res_f, f'{{{ft_ns}}}name').text = fname; ET.SubElement(res_f, f'{{{ft_ns}}}size').text = str(fsize)

                if s5b_t is not None:
                    res_t = ET.SubElement(res_c, '{urn:xmpp:jingle:transports:s5b:1}transport', {'sid': transport_sid, 'mode': 'tcp'})

                    # Direct candidate
                    local_ip = self.get_local_ip()
                    ET.SubElement(res_t, '{urn:xmpp:jingle:transports:s5b:1}candidate',
                                  host=local_ip, port='1080', jid=self.bot.boundjid.full,
                                  cid='direct-host', priority='8253074', type='host')

                    # Proxy candidates
                    for p_host, p_jid in [('proxy.eu.jabber.network', 'proxy.eu.jabber.network'), ('proxy.jabber.ru', 'proxy.jabber.ru')]:
                        ET.SubElement(res_t, '{urn:xmpp:jingle:transports:s5b:1}candidate', host=p_host, port='1080', jid=p_jid, cid=hashlib.md5(p_jid.encode()).hexdigest(), priority='65536', type='proxy')
                elif ibb_t is not None:
                    ET.SubElement(res_c, '{urn:xmpp:jingle:transports:ibb:1}transport', {'block-size': '4096', 'sid': transport_sid})
                else:
                    ET.SubElement(res_c, '{urn:xmpp:jingle:transports:ibb:1}transport', {'block-size': '4096', 'sid': sid})

                accept_iq.append(res_j); accept_iq.send()
                if s5b_t is not None and s5b_t.findall('{urn:xmpp:jingle:transports:s5b:1}candidate'):
                    self.bot.pending_files[sid]['s5b_connecting'] = True
                    self.bot.pending_files[f"jingle_s5b_{sid}"] = asyncio.create_task(self._socks5_connect_and_save(iq, jingle_sid=sid))
            except Exception as e: logging.error(f"JINGLE ERROR: {e}")
        elif action == 'transport-info':
            content = jingle.find('{urn:xmpp:jingle:1}content')
            if content is not None:
                transport = content.find('{urn:xmpp:jingle:transports:s5b:1}transport')
                if transport is not None and not self.bot.pending_files.get(sid, {}).get('s5b_connecting'):
                    self.bot.pending_files[sid]['s5b_connecting'] = True
                    self.bot.pending_files[f"jingle_s5b_info_{sid}"] = asyncio.create_task(self._socks5_connect_and_save(iq, jingle_sid=sid))
            iq.reply().send()
        elif action == 'transport-replace':
            content = jingle.find('{urn:xmpp:jingle:1}content')
            if content is not None:
                ibb_t = content.find('{urn:xmpp:jingle:transports:ibb:1}transport')
                if ibb_t is not None:
                    if sid in self.bot.pending_files:
                        ibb_sid = ibb_t.get('sid')
                        self.bot.pending_files[sid]['transport_sid'] = ibb_sid
                        self.bot.pending_files[ibb_sid] = self.bot.pending_files[sid]
                        reply = self.bot.make_iq_set(ito=iq['from'])
                        res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {'action': 'transport-accept', 'sid': sid})
                        res_c = ET.SubElement(res_j, '{urn:xmpp:jingle:1}content', {
                            'creator': content.get('creator'), 'name': content.get('name')
                        })
                        ET.SubElement(res_c, '{urn:xmpp:jingle:transports:ibb:1}transport', {'sid': ibb_t.get('sid')})
                        reply.append(res_j); reply.send()
            iq.reply().send()
        elif action == 'transport-accept':
            iq.reply().send()
        elif action == 'session-terminate':
            if sid in self.bot.pending_files: del self.bot.pending_files[sid]
            iq.reply().send()

    def handle_raw_si(self, iq):
        logging.info(f"SI REQUEST from {iq['from']}")
        if not self.bot.is_allowed(iq['from']):
            reply = iq.error()
            reply['error']['condition'] = 'not-authorized'
            reply.send()
            return
        try:
            si = iq.xml.find('{http://jabber.org/protocol/si}si')
            if si is None: return
            tag = si.find('{http://jabber.org/protocol/si/profile/file-transfer}file')
            if tag is None: return

            fname_raw = tag.get('name')
            if not fname_raw: return

            if self.is_php(fname_raw):
                self.bot.send_message(mto=iq['from'], mbody="❌ Ошибка: Загрузка PHP-файлов запрещена!", mtype='chat')
                reply = iq.error()
                reply['error']['condition'] = 'not-acceptable'
                reply.send(); return

            sid = si.get('id')
            fname, fsize = os.path.basename(fname_raw).replace(' ', '_'), int(tag.get('size', 0))
            user_dir, _ = self.bot.get_user_info(iq['from'])
            if get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                reply = iq.error()
                reply['error']['condition'] = 'resource-constraint'
                reply.send(); return
            feature_neg = si.find('{http://jabber.org/protocol/feature-neg}feature')
            offered_methods = []
            if feature_neg is not None:
                x_data = feature_neg.find('{jabber:x:data}x')
                if x_data is not None:
                    field = next((f for f in x_data.findall('{jabber:x:data}field') if f.get('var') == 'stream-method'), None)
                    if field is not None:
                        offered_methods = [v.text for v in field.findall('{jabber:x:data}value')]
                        offered_methods.extend([v.text for v in field.findall('{jabber:x:data}option/{jabber:x:data}value')])
            chosen_method = next((m for m in ['jabber:iq:oob', 'http://jabber.org/protocol/bytestreams', 'http://jabber.org/protocol/ibb'] if m in offered_methods), None)
            if not chosen_method:
                reply = iq.reply(); reply['type'] = 'error'; return reply.send()
            self.bot.pending_files[sid] = {
                'name': fname, 'size': fsize, 'timestamp': asyncio.get_event_loop().time(),
                'ibb_allowed': 'http://jabber.org/protocol/ibb' in offered_methods,
                'peer_jid': iq['from'], 'transport_sid': sid
            }
            reply = iq.reply()
            res_si = ET.Element('{http://jabber.org/protocol/si}si')
            feature = ET.SubElement(res_si, '{http://jabber.org/protocol/feature-neg}feature')
            x = ET.SubElement(feature, '{jabber:x:data}x', type='submit')
            field = ET.SubElement(x, '{jabber:x:data}field', var='stream-method')
            ET.SubElement(field, '{jabber:x:data}value').text = chosen_method
            reply.append(res_si); reply.send()
        except Exception as e:
            logging.error(f"SI ERROR: {e}", exc_info=True)
            try:
                reply = iq.error()
                reply['error']['condition'] = 'internal-server-error'
                reply.send()
            except: pass

    def handle_raw_s5b(self, iq):
        logging.info(f"S5B REQUEST from {iq['from']}:\n{ET.tostring(iq.xml, encoding='unicode')}")
        query = iq.xml.find('{http://jabber.org/protocol/bytestreams}query')
        if query is not None and query.find('{http://jabber.org/protocol/bytestreams}streamhost-used') is not None:
             asyncio.create_task(self._socks5_connect_and_save(iq))
        else:
             self.bot.pending_files[f"s5b_{iq['id']}"] = asyncio.create_task(self._socks5_connect_and_save(iq))

    async def _socks5_connect_and_save(self, iq, jingle_sid=None):
        sid = None
        try:
            if jingle_sid:
                sid = jingle_sid; jingle = iq.xml.find('{urn:xmpp:jingle:1}jingle')
                if jingle is None: return
                content = jingle.find('{urn:xmpp:jingle:1}content')
                if content is None: return
                query = content.find('{urn:xmpp:jingle:transports:s5b:1}transport')
                if query is None: return
                hosts = query.findall('{urn:xmpp:jingle:transports:s5b:1}candidate')
                peer_full = iq['from'].full
            else:
                query = iq.xml.find('{http://jabber.org/protocol/bytestreams}query')
                if query is None: return
                sid, peer_full = query.get('sid'), iq['from'].full
                used = query.find('{http://jabber.org/protocol/bytestreams}streamhost-used')
                if used is not None:
                    jid = used.get('jid'); proxy = self.KNOWN_PROXIES.get(jid)
                    if proxy: hosts = [ET.Element('streamhost', host=proxy['host'], port=str(proxy['port']), jid=jid)]
                    else: reply = iq.reply(); reply['type'] = 'error'; reply.send(); return
                else:
                    hosts = query.findall('{http://jabber.org/protocol/bytestreams}streamhost')
                if not hosts and used is None:
                    reply = iq.reply(); res_q = ET.Element('{http://jabber.org/protocol/bytestreams}query', {'sid': sid})
                    for p_jid, p_info in self.KNOWN_PROXIES.items():
                        ET.SubElement(res_q, 'streamhost', host=p_info['host'], port=str(p_info['port']), jid=p_jid)
                    reply.append(res_q); reply.send(); return
            file_info = self.bot.pending_files.get(sid)
            if not file_info: return
            t_sid = file_info.get('transport_sid', sid)
            dst_addr = hashlib.sha1(f"{t_sid}{peer_full}{self.bot.boundjid.full}".encode()).hexdigest()

            if jingle_sid and not hosts:
                jingle = iq.xml.find('{urn:xmpp:jingle:1}jingle')
                if jingle is not None and jingle.get('action') == 'session-initiate':
                    self.bot.pending_files[sid]['s5b_connecting'] = False
                    return

            for host in hosts:
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host.get('host'), int(host.get('port', 1080))), 5)
                    writer.write(b"\x05\x01\x00"); await writer.drain()
                    if await reader.read(2) != b"\x05\x00": writer.close(); continue
                    writer.write(b"\x05\x01\x00\x03" + bytes([len(dst_addr)]) + dst_addr.encode() + b"\x00\x00"); await writer.drain()
                    resp = await reader.read(4)
                    if not resp or resp[1] != 0x00: writer.close(); continue
                    atyp = resp[3]
                    if atyp == 0x01: await reader.read(6)
                    elif atyp == 0x03: addr_len = await reader.read(1); await reader.read(addr_len[0] + 2)
                    elif atyp == 0x04: await reader.read(18)
                    if jingle_sid:
                        reply = self.bot.make_iq_set(ito=iq['from'])
                        res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {'action': 'transport-info', 'sid': jingle_sid})
                        res_c = ET.SubElement(res_j, '{urn:xmpp:jingle:1}content', {'creator': file_info.get('content_creator', 'initiator'), 'name': file_info.get('content_name', 'file')})
                        res_t = ET.SubElement(res_c, '{urn:xmpp:jingle:transports:s5b:1}transport', {'sid': sid})
                        ET.SubElement(res_t, 'candidate-used', cid=host.get('cid'))
                        reply.append(res_j); reply.send()
                    else:
                        reply = iq.reply()
                        if used is None:
                            res_q = ET.Element('{http://jabber.org/protocol/bytestreams}query', {'sid': sid})
                            ET.SubElement(res_q, 'streamhost-used', jid=host.get('jid'))
                            reply.append(res_q)
                        reply.send()
                    await self.download_file_task(reader, file_info, iq['from'], sid); writer.close(); await writer.wait_closed(); return
                except Exception: continue
            if not jingle_sid:
                reply = iq.reply(); reply['type'] = 'error'; reply.send()
            elif file_info.get('ibb_allowed'):
                logging.info(f"SOCKS5 failed for Jingle sid={sid}, falling back to IBB")
                new_ibb_sid = f"fallback_{sid}"
                self.bot.pending_files[sid]['transport_sid'] = new_ibb_sid
                self.bot.pending_files[new_ibb_sid] = self.bot.pending_files[sid]

                reply = self.bot.make_iq_set(ito=iq['from'])
                res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {'action': 'transport-replace', 'sid': sid})
                res_c = ET.SubElement(res_j, '{urn:xmpp:jingle:1}content', {
                    'creator': file_info.get('content_creator', 'initiator'),
                    'name': file_info.get('content_name', 'file')
                })
                ET.SubElement(res_c, '{urn:xmpp:jingle:transports:ibb:1}transport', {
                    'sid': new_ibb_sid, 'block-size': '4096'
                })
                reply.append(res_j); reply.send()

            if not file_info.get('ibb_allowed'):
                if sid in self.bot.pending_files: del self.bot.pending_files[sid]
        except Exception as e: logging.error(f"SOCKS5 ERROR: {e}")

    def handle_ibb_stream(self, stream):
        sid = stream.sid
        file_info = self.bot.pending_files.get(sid)
        if file_info:
            if file_info['peer_jid'].bare != stream.peer_jid.bare:
                stream.close(); return
            logging.info(f"IBB stream started for sid={sid}")
            self.bot.pending_files[f"task_{sid}"] = asyncio.create_task(self.download_file_task(stream, file_info, stream.peer_jid, sid))
        else: stream.close()

    async def download_file_task(self, reader, file_info, peer_jid, sid):
        user_dir, user_hash = self.bot.get_user_info(peer_jid)
        path = get_unique_path(os.path.join(user_dir, os.path.basename(file_info['name'])))
        received, loop = 0, asyncio.get_event_loop()
        try:
            with open(path, 'wb') as f:
                while received < file_info['size']:
                    if hasattr(reader, 'recv_queue'): chunk = await reader.recv_queue.get()
                    else: chunk = await reader.read(min(file_info['size'] - received, 1048576))
                    if not chunk: break
                    await loop.run_in_executor(None, f.write, chunk); received += len(chunk)
                await loop.run_in_executor(None, f.flush); await loop.run_in_executor(None, os.fsync, f.fileno())
            if received == file_info['size']:
                self.bot.send_message(mto=peer_jid, mbody=f"✅ Готово!\n{self.bot.base_url}/{user_hash}/{safe_quote(os.path.basename(path))}", mtype='chat')
            else:
                if os.path.exists(path): os.remove(path)
        except Exception as e:
            logging.error(f"DOWNLOAD ERROR: {e}")
            if os.path.exists(path): os.remove(path)
        finally:
            info = self.bot.pending_files.get(sid)
            if info:
                t_sid = info.get('transport_sid')
                if t_sid and t_sid in self.bot.pending_files: del self.bot.pending_files[t_sid]
            if sid in self.bot.pending_files: del self.bot.pending_files[sid]
