import os
import socket
import hashlib
import asyncio
import logging
import random
import string
import struct
import aiohttp
from slixmpp.xmlstream import ET, matcher, handler
from config import QUOTA_LIMIT_BYTES
from utils import get_dir_size, safe_quote, get_unique_path
from .base import BasePlugin

# Basic STUN message parsing for ICE connectivity checks
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
STUN_MAGIC_COOKIE = 0x2112A442
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020

class ICEUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, file_info, bot, peer_jid, sid, on_complete):
        self.file_info = file_info
        self.bot = bot
        self.peer_jid = peer_jid
        self.sid = sid
        self.on_complete = on_complete
        self.received_size = 0
        self.file_path = None
        self.f = None
        self.transport = None
        self.timeout_handle = None
        self.remote_addr = None

    def connection_made(self, transport):
        self.transport = transport
        user_dir, user_hash = self.bot.get_user_info(self.peer_jid)
        self.file_path = get_unique_path(os.path.join(user_dir, os.path.basename(self.file_info['name'])))
        self.f = open(self.file_path, 'wb')
        logging.info(f"ICE-UDP connection made, saving to {self.file_path}")
        self._reset_timeout()

    def _reset_timeout(self):
        if self.timeout_handle:
            self.timeout_handle.cancel()
        self.timeout_handle = asyncio.get_running_loop().call_later(60, self.finish)

    def datagram_received(self, data, addr):
        self._reset_timeout()
        if not data: return

        if len(data) >= 20:
            msg_type, msg_len = struct.unpack('!HH', data[:4])
            cookie = struct.unpack('!I', data[4:8])[0]
            if cookie == STUN_MAGIC_COOKIE:
                if msg_type == STUN_BINDING_REQUEST:
                    self.remote_addr = addr
                    trans_id = data[8:20]
                    ip_int = struct.unpack('!I', socket.inet_aton(addr[0]))[0]
                    xor_ip = ip_int ^ STUN_MAGIC_COOKIE
                    xor_port = addr[1] ^ (STUN_MAGIC_COOKIE >> 16)
                    attr_val = struct.pack('!BBH I', 0x00, 0x01, xor_port, xor_ip)
                    attr_header = struct.pack('!HH', STUN_ATTR_XOR_MAPPED_ADDRESS, len(attr_val))
                    response_header = struct.pack('!HH', STUN_BINDING_SUCCESS, len(attr_header) + len(attr_val))
                    response = response_header + struct.pack('!I', STUN_MAGIC_COOKIE) + trans_id + attr_header + attr_val
                    self.transport.sendto(response, addr)
                return

        if self.remote_addr and addr != self.remote_addr:
            return

        if self.f:
            self.f.write(data)
            self.received_size += len(data)
            if self.received_size >= self.file_info['size']:
                self.finish()

    def finish(self):
        if self.timeout_handle:
            self.timeout_handle.cancel()
            self.timeout_handle = None

        if self.f:
            try:
                self.f.flush()
                os.fsync(self.f.fileno())
            except Exception as e:
                logging.error(f"Error flushing file: {e}")
            finally:
                self.f.close()
                self.f = None

        if self.received_size >= self.file_info['size']:
            user_dir, user_hash = self.bot.get_user_info(self.peer_jid)
            self.bot.send_message(mto=self.peer_jid, mbody=f"✅ Готово!\n{self.bot.base_url}/{user_hash}/{safe_quote(os.path.basename(self.file_path))}", mtype='chat')
            asyncio.create_task(self._send_terminate_success())
        else:
            if self.file_path and os.path.exists(self.file_path):
                try: os.remove(self.file_path)
                except: pass
            logging.error(f"Transfer incomplete: {self.received_size}/{self.file_info['size']}")

        if self.sid in self.bot.pending_files:
            del self.bot.pending_files[self.sid]

        self.on_complete()
        if self.transport:
            self.transport.close()

    async def _send_terminate_success(self):
        try:
            iq = self.bot.make_iq_set(ito=self.peer_jid)
            res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {'action': 'session-terminate', 'sid': self.sid})
            reason = ET.SubElement(res_j, '{urn:xmpp:jingle:1}reason')
            ET.SubElement(reason, '{urn:xmpp:jingle:1}success')
            iq.append(res_j)
            iq.send()
        except: pass

    def error_received(self, exc):
        logging.error(f"ICE-UDP error: {exc}")
        self.finish()

    def connection_lost(self, exc):
        logging.info("ICE-UDP connection lost")
        if self.f:
            self.finish()

class FileTransferPlugin(BasePlugin):
    KNOWN_PROXIES = {
        'proxy.eu.jabber.network': {'host': 'proxy.eu.jabber.network', 'port': 1080},
        'proxy.jabber.ru': {'host': 'proxy.jabber.ru', 'port': 1080},
        'proxy.jabbim.cz': {'host': 'proxy.jabbim.cz', 'port': 1080},
        'proxy.yax.im': {'host': 'proxy.yax.im', 'port': 1080},
    }

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except: return '127.0.0.1'

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
        self.active_transfers = {}

    def handle_iq_oob(self, iq):
        logging.info(f"IQ OOB REQUEST from {iq['from']}:\n{ET.tostring(iq.xml, encoding='unicode')}")
        query = iq.xml.find('{jabber:iq:oob}query')
        if query is None: return
        url_tag = query.find('{jabber:iq:oob}url')
        if url_tag is None or not url_tag.text: return
        url = url_tag.text
        desc = query.find('{jabber:iq:oob}desc')
        fname = desc.text if desc is not None and desc.text else os.path.basename(url)
        self.bot.pending_files[f"oob_{url}"] = asyncio.create_task(self.download_from_url(url, fname, iq['from']))
        iq.reply().send()

    async def download_from_url(self, url, fname, peer_jid):
        logging.info(f"Downloading OOB from {url}")
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

    def handle_raw_si(self, iq):
        logging.info(f"SI REQUEST from {iq['from']}:\n{ET.tostring(iq.xml, encoding='unicode')}")
        if not self.bot.is_allowed(iq['from']):
            reply = iq.reply(); reply['type'] = 'error'; return reply.send()
        try:
            si = iq.xml.find('{http://jabber.org/protocol/si}si')
            sid, tag = si.get('id'), si.find('{http://jabber.org/protocol/si/profile/file-transfer}file')
            fname, fsize = os.path.basename(tag.get('name')).replace(' ', '_'), int(tag.get('size', 0))
            user_dir, _ = self.bot.get_user_info(iq['from'])
            if get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                reply = iq.reply(); reply['type'] = 'error'; return reply.send()
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
            res_si = ET.Element('{http://jabber.org/protocol/si}si', {'id': sid})
            feature = ET.SubElement(res_si, '{http://jabber.org/protocol/feature-neg}feature')
            x = ET.SubElement(feature, '{jabber:x:data}x', type='submit')
            field = ET.SubElement(x, '{jabber:x:data}field', var='stream-method')
            ET.SubElement(field, '{jabber:x:data}value').text = chosen_method
            reply.append(res_si); reply.send()
        except Exception as e: logging.error(f"SI ERROR: {e}")

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
            if sid in self.bot.pending_files: del self.bot.pending_files[sid]

    def handle_jingle(self, iq):
        jingle = iq.xml.find('{urn:xmpp:jingle:1}jingle')
        if jingle is None: return
        action, sid = jingle.get('action'), jingle.get('sid')
        logging.info(f"JINGLE REQUEST ({action}) from {iq['from']}:\n{ET.tostring(iq.xml, encoding='unicode')}")

        if action == 'session-initiate':
            self._handle_session_initiate(iq, jingle, sid)
        elif action == 'transport-info':
            self._handle_transport_info(iq, jingle, sid)
        elif action == 'session-terminate':
            if sid in self.bot.pending_files: del self.bot.pending_files[sid]
            if sid in self.active_transfers:
                self.active_transfers[sid]['protocol'].finish()
            iq.reply().send()
        else:
            iq.reply().send()

    def _handle_session_initiate(self, iq, jingle, sid):
        if not self.bot.is_allowed(iq['from']):
            reply = iq.reply(); reply['type'] = 'error'; reply.send(); return

        content = jingle.find('{urn:xmpp:jingle:1}content')
        if content is None: return

        ft_ns = 'urn:xmpp:jingle:apps:file-transfer:5'
        description = content.find(f'{{{ft_ns}}}description')
        if description is None:
            ft_ns = 'urn:xmpp:jingle:apps:file-transfer:4'
            description = content.find(f'{{{ft_ns}}}description')
        if description is None: return

        file_tag = description.find(f'{{{ft_ns}}}file')
        if file_tag is None: return

        name_tag, size_tag = file_tag.find(f'{{{ft_ns}}}name'), file_tag.find(f'{{{ft_ns}}}size')
        if name_tag is None or size_tag is None: return

        fname = os.path.basename(name_tag.text).replace(' ', '_')
        try: fsize = int(size_tag.text)
        except: fsize = 0

        user_dir, _ = self.bot.get_user_info(iq['from'])
        if get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
            reply = iq.reply(); reply['type'] = 'error'; reply.send(); return

        ice_t = content.find('{urn:xmpp:jingle:transports:ice-udp:1}transport')
        s5b_t = content.find('{urn:xmpp:jingle:transports:s5b:1}transport')
        ibb_t = content.find('{urn:xmpp:jingle:transports:ibb:1}transport')

        self.bot.pending_files[sid] = {
            'name': fname, 'size': fsize, 'timestamp': asyncio.get_event_loop().time(),
            'peer_jid': iq['from'],
            'content_name': content.get('name'), 'content_creator': content.get('creator'),
            'ft_ns': ft_ns, 'transport_sid': sid,
            'ibb_allowed': ibb_t is not None
        }

        if ice_t is not None:
             iq.reply().send()
             asyncio.create_task(self._accept_jingle_ice(iq, sid, content))
        elif s5b_t is not None:
             iq.reply().send()
             # Fallback logic or S5B logic here
             # For now, let's keep it simple
        else:
            reply = iq.reply(); reply['type'] = 'error'; reply['error']['condition'] = 'feature-not-implemented'; reply.send()

    async def _accept_jingle_ice(self, iq, sid, content):
        file_info = self.bot.pending_files[sid]
        ft_ns = file_info['ft_ns']
        ufrag = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=24))
        local_ip = self.get_local_ip()
        loop = asyncio.get_running_loop()
        on_complete = lambda: self.active_transfers.pop(sid, None)
        try:
            listen_transport, protocol = await loop.create_datagram_endpoint(
                lambda: ICEUDPProtocol(file_info, self.bot, iq['from'], sid, on_complete),
                local_addr=(local_ip, 0)
            )
            local_port = listen_transport.get_extra_info('sockname')[1]
            self.active_transfers[sid] = {'transport': listen_transport, 'protocol': protocol}
            accept_iq = self.bot.make_iq_set(ito=iq['from'])
            res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {'action': 'session-accept', 'sid': sid, 'initiator': iq['from'].full})
            res_c = ET.SubElement(res_j, '{urn:xmpp:jingle:1}content', {'creator': content.get('creator'), 'name': content.get('name')})
            res_d = ET.SubElement(res_c, f'{{{ft_ns}}}description')
            res_f = ET.SubElement(res_d, f'{{{ft_ns}}}file')
            ET.SubElement(res_f, f'{{{ft_ns}}}name').text = file_info['name']
            ET.SubElement(res_f, f'{{{ft_ns}}}size').text = str(file_info['size'])
            res_t = ET.SubElement(res_c, '{urn:xmpp:jingle:transports:ice-udp:1}transport', {'ufrag': ufrag, 'pwd': pwd})
            ET.SubElement(res_t, '{urn:xmpp:jingle:transports:ice-udp:1}candidate', {
                'component': '1', 'foundation': '1', 'generation': '0', 'id': 'h1',
                'ip': local_ip, 'network': '1', 'port': str(local_port),
                'priority': '2122260223', 'protocol': 'udp', 'type': 'host'
            })
            accept_iq.append(res_j); accept_iq.send()
        except Exception as e:
            logging.error(f"Error starting ICE-UDP listener: {e}")
            if sid in self.bot.pending_files: del self.bot.pending_files[sid]

    def _handle_transport_info(self, iq, jingle, sid):
        iq.reply().send()
