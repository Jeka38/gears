import os
import socket
import hashlib
import asyncio
import logging
import random
import string
import struct
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

        # Check if it's a STUN packet (Binding Request)
        if len(data) >= 20:
            msg_type, msg_len = struct.unpack('!HH', data[:4])
            cookie = struct.unpack('!I', data[4:8])[0]
            if cookie == STUN_MAGIC_COOKIE:
                if msg_type == STUN_BINDING_REQUEST:
                    self.remote_addr = addr
                    trans_id = data[8:20]

                    # XOR-MAPPED-ADDRESS
                    ip_int = struct.unpack('!I', socket.inet_aton(addr[0]))[0]
                    xor_ip = ip_int ^ STUN_MAGIC_COOKIE
                    xor_port = addr[1] ^ (STUN_MAGIC_COOKIE >> 16)

                    attr_val = struct.pack('!BBH I', 0x00, 0x01, xor_port, xor_ip)
                    attr_header = struct.pack('!HH', STUN_ATTR_XOR_MAPPED_ADDRESS, len(attr_val))

                    response_header = struct.pack('!HH', STUN_BINDING_SUCCESS, len(attr_header) + len(attr_val))
                    response = response_header + struct.pack('!I', STUN_MAGIC_COOKIE) + trans_id + attr_header + attr_val

                    self.transport.sendto(response, addr)
                    logging.debug(f"STUN Binding Request from {addr}, sent success response with XOR-MAPPED-ADDRESS")
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
            handler.Callback('Jingle', matcher.MatchXPath('{jabber:client}iq/{urn:xmpp:jingle:1}jingle'), self.handle_jingle)
        )
        self.active_transfers = {}

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
        if ice_t is None:
            reply = iq.reply(); reply['type'] = 'error'; reply['error']['condition'] = 'feature-not-implemented'; reply.send(); return

        self.bot.pending_files[sid] = {
            'name': fname, 'size': fsize, 'timestamp': asyncio.get_event_loop().time(),
            'peer_jid': iq['from'],
            'content_name': content.get('name'), 'content_creator': content.get('creator'),
            'ft_ns': ft_ns, 'transport_sid': sid
        }
        iq.reply().send()

        asyncio.create_task(self._accept_jingle_ice(iq, sid, content))

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
                'component': '1',
                'foundation': '1',
                'generation': '0',
                'id': 'h1',
                'ip': local_ip,
                'network': '1',
                'port': str(local_port),
                'priority': '2122260223',
                'protocol': 'udp',
                'type': 'host'
            })

            accept_iq.append(res_j)
            accept_iq.send()
        except Exception as e:
            logging.error(f"Error starting ICE-UDP listener: {e}")
            if sid in self.bot.pending_files: del self.bot.pending_files[sid]

    def _handle_transport_info(self, iq, jingle, sid):
        iq.reply().send()
