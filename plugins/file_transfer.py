import os
import socket
import hashlib
import asyncio
import logging
import aiohttp
import base64
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

    def is_private_ip(self, ip):
        try:
            if ':' in ip: return ip.startswith('fe80') or ip.startswith('::1') or ip.startswith('fd')
            parts = list(map(int, ip.split('.')))
            if parts[0] == 10: return True
            if parts[0] == 172 and 16 <= parts[1] <= 31: return True
            if parts[0] == 192 and parts[1] == 168: return True
            if parts[0] == 127: return True
            return False
        except: return False

    KNOWN_PROXIES = {
        'proxy.eu.jabber.network': {'host': 'proxy.eu.jabber.network', 'port': 1080},
        'proxy.jabber.ru': {'host': 'proxy.jabber.ru', 'port': 1080},
        'proxy.jabbim.cz': {'host': 'proxy.jabbim.cz', 'port': 1080},
        'proxy.yax.im': {'host': 'proxy.yax.im', 'port': 1080},
        'proxy.jabberworld.info': {'host': '185.161.208.229', 'port': 7777},
    }

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
        self.bot.register_handler(
            handler.Callback('BoB', matcher.MatchXPath('{jabber:client}iq/{urn:xmpp:bob}data'), self.handle_bob)
        )
        self.bot.add_event_handler("ibb_stream_start", self.handle_ibb_stream)
        self.bot.add_event_handler("ibb_stream_request", self.handle_ibb_stream_request)
        self.bot.add_event_handler("session_start", self.on_session_start, disposable=True)

    async def on_session_start(self, event):
        asyncio.create_task(self.discover_proxies())

    async def discover_proxies(self):
        logging.info("S5B: Discovering proxies...")
        try:
            # Query server for items
            items = await self.bot['xep_0030'].get_items(jid=self.bot.boundjid.domain)
            for item in items['disco_items']:
                try:
                    info = await self.bot['xep_0030'].get_info(jid=item['jid'])
                    identities = info['disco_info']['identities']
                    if any(identity[0] == 'proxy' and identity[1] == 'bytestreams' for identity in identities):
                        logging.info(f"S5B: Found proxy {item['jid']}")
                        # Query proxy for streamhosts
                        res = await self.bot.make_iq_get(ito=item['jid']).append(ET.Element('{http://jabber.org/protocol/bytestreams}query')).send()
                        query = res.xml.find('{http://jabber.org/protocol/bytestreams}query')
                        if query is not None:
                            for sh in query.findall('{http://jabber.org/protocol/bytestreams}streamhost'):
                                self.KNOWN_PROXIES[sh.get('jid')] = {'host': sh.get('host'), 'port': int(sh.get('port', 1080))}
                                logging.info(f"S5B: Added discovered proxy streamhost: {sh.get('jid')} -> {sh.get('host')}:{sh.get('port')}")
                except Exception as e:
                    logging.debug(f"S5B: Failed to get info for {item['jid']}: {e}")
            # Also try the server domain itself, some servers have proxy on the main domain
            try:
                info = await self.bot['xep_0030'].get_info(jid=self.bot.boundjid.domain)
                if any(identity[0] == 'proxy' and identity[1] == 'bytestreams' for identity in info['disco_info']['identities']):
                     res = await self.bot.make_iq_get(ito=self.bot.boundjid.domain).append(ET.Element('{http://jabber.org/protocol/bytestreams}query')).send()
                     query = res.xml.find('{http://jabber.org/protocol/bytestreams}query')
                     if query is not None:
                         for sh in query.findall('{http://jabber.org/protocol/bytestreams}streamhost'):
                             self.KNOWN_PROXIES[sh.get('jid')] = {'host': sh.get('host'), 'port': int(sh.get('port', 1080))}
                             logging.info(f"S5B: Added discovered server proxy streamhost: {sh.get('jid')} -> {sh.get('host')}:{sh.get('port')}")
            except: pass
        except Exception as e:
            logging.error(f"S5B: Proxy discovery failed: {e}")

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

    def handle_bob(self, iq):
        if iq['type'] != 'result': return
        data_tag = iq.xml.find('{urn:xmpp:bob}data')
        if data_tag is None or not data_tag.text: return
        cid = data_tag.get('cid')
        fname = self.bot.pending_files.get(f"bob_{cid}")
        if not fname: return
        try:
            raw_data = base64.b64decode(data_tag.text)
            user_dir, _ = self.bot.get_user_info(iq['from'])
            # Security: Sanitize filename to prevent path traversal
            safe_fname = os.path.basename(fname)
            ext = "png"
            mime = data_tag.get('type')
            if mime:
                if '/' in mime: ext = mime.split('/')[1]
                if ';' in ext: ext = ext.split(';')[0]
            thumb_path = os.path.join(user_dir, f"{safe_fname}.thumb.{ext}")
            with open(thumb_path, 'wb') as f: f.write(raw_data)
            logging.info(f"Saved thumbnail to {thumb_path}")
        except Exception as e: logging.error(f"BoB error: {e}")
        finally:
            if f"bob_{cid}" in self.bot.pending_files: del self.bot.pending_files[f"bob_{cid}"]

    def handle_jingle(self, iq):
        jingle = iq.xml.find('{urn:xmpp:jingle:1}jingle')
        if jingle is None: return
        action, sid = jingle.get('action'), jingle.get('sid')
        logging.info(f"JINGLE REQUEST ({action}) from {iq['from']}:\n{ET.tostring(iq.xml, encoding='unicode')}")
        if action == 'session-initiate':
            if not self.bot.is_allowed(iq['from']):
                reply = iq.reply(); reply['type'] = 'error'; reply.send(); return
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
            fname, transport_sid = os.path.basename(name_tag.text).replace(' ', '_'), sid
            try: fsize = int(size_tag.text)
            except: fsize = 0
            user_dir, _ = self.bot.get_user_info(iq['from'])
            if get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                reply = iq.reply(); reply['type'] = 'error'; reply.send(); return

            ibb_t = content.find('{urn:xmpp:jingle:transports:ibb:1}transport')
            s5b_t = content.find('{urn:xmpp:jingle:transports:s5b:1}transport')
            ice_t = content.find('{urn:xmpp:jingle:transports:ice:0}transport')
            if ice_t is None: ice_t = content.find('{urn:xmpp:jingle:transports:ice-udp:1}transport')

            # Prioritize: S5B > IBB > ICE
            if s5b_t is not None and s5b_t.get('sid'): transport_sid = s5b_t.get('sid')
            elif ibb_t is not None and ibb_t.get('sid'): transport_sid = ibb_t.get('sid')
            elif ice_t is not None and ice_t.get('sid'): transport_sid = ice_t.get('sid')
            else: transport_sid = sid

            initiator = jingle.get('initiator') or iq['from'].full
            peer_dstaddr = s5b_t.get('dstaddr') if s5b_t is not None else None
            self.bot.pending_files[sid] = {
                'name': fname, 'size': fsize, 'timestamp': asyncio.get_event_loop().time(),
                'peer_dstaddr': peer_dstaddr,
                'peer_jid': iq['from'], 'ibb_allowed': True,
                'content_name': content.get('name'), 'content_creator': content.get('creator'),
                'ft_ns': ft_ns, 'transport_sid': transport_sid, 's5b_connecting': False,
                'jingle': True, 'session_sid': sid, 'initiator': initiator,
                'responder': self.bot.boundjid.full
            }
            if transport_sid != sid: self.bot.pending_files[transport_sid] = self.bot.pending_files[sid]
            iq.reply().send()

            # Thumbnail handling (BoB)
            thumb = file_tag.find('{urn:xmpp:thumbs:1}thumbnail')
            if thumb is not None and thumb.get('uri') and thumb.get('uri').startswith('cid:'):
                cid = thumb.get('uri')[4:]
                self.bot.pending_files[f"bob_{cid}"] = fname
                bob_iq = self.bot.make_iq_get(ito=iq['from'])
                bob_iq.append(ET.Element('{urn:xmpp:bob}data', cid=cid))
                bob_iq.send()

            try:
                accept_iq = self.bot.make_iq_set(ito=iq['from'])
                res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {
                    'action': 'session-accept', 'sid': sid,
                    'initiator': initiator, 'responder': self.bot.boundjid.full
                })
                res_c = ET.SubElement(res_j, '{urn:xmpp:jingle:1}content', {'creator': content.get('creator'), 'name': content.get('name')})
                res_d = ET.SubElement(res_c, f'{{{ft_ns}}}description')
                res_f = ET.SubElement(res_d, f'{{{ft_ns}}}file')
                ET.SubElement(res_f, f'{{{ft_ns}}}name').text = fname; ET.SubElement(res_f, f'{{{ft_ns}}}size').text = str(fsize)

                if s5b_t is not None:
                    # Jingle S5B: dstaddr = SHA-1(SID + RequesterJID + TargetJID)
                    # For our candidates, Bot is Requester, Peer (initiator) is Target
                    dst_addr = hashlib.sha1(f"{transport_sid}{self.bot.boundjid.full}{initiator}".encode()).hexdigest()
                    res_t = ET.SubElement(res_c, '{urn:xmpp:jingle:transports:s5b:1}transport', {'sid': transport_sid, 'mode': 'tcp', 'dstaddr': dst_addr})
                    local_ip = self.get_local_ip()
                    ET.SubElement(res_t, '{urn:xmpp:jingle:transports:s5b:1}candidate',
                                  host=local_ip, port='1080', jid=self.bot.boundjid.full,
                                  cid='direct-host', priority='8253074', type='host')
                    for p_jid, p_info in self.KNOWN_PROXIES.items():
                        ET.SubElement(res_t, '{urn:xmpp:jingle:transports:s5b:1}candidate', host=p_info['host'], port=str(p_info['port']), jid=p_jid, cid=hashlib.md5(p_jid.encode()).hexdigest(), priority='65536', type='proxy')
                elif ice_t is not None:
                    ice_ns = ice_t.tag.split('}')[0].strip('{')
                    ET.SubElement(res_c, f'{{{ice_ns}}}transport', {'ufrag': 'botufrag', 'pwd': 'botpassword'})
                elif ibb_t is not None:
                    ET.SubElement(res_c, '{urn:xmpp:jingle:transports:ibb:1}transport', {'block-size': '4096', 'sid': transport_sid})
                else:
                    ET.SubElement(res_c, '{urn:xmpp:jingle:transports:ibb:1}transport', {'block-size': '4096', 'sid': sid})

                accept_iq.append(res_j); accept_iq.send()

                # If we accepted non-S5B, immediately try to upgrade to S5B
                if s5b_t is None:
                    asyncio.create_task(self._initiate_transport_replace_s5b(iq, sid))
                elif s5b_t.findall('{urn:xmpp:jingle:transports:s5b:1}candidate'):
                    self.bot.pending_files[sid]['s5b_connecting'] = True
                    t_key = f"jingle_s5b_{sid}"
                    self.bot.pending_files[t_key] = asyncio.create_task(self._socks5_connect_and_save(iq, jingle_sid=sid, task_key=t_key))
            except Exception as e: logging.error(f"JINGLE ERROR: {e}")
        elif action == 'transport-info':
            content = jingle.find('{urn:xmpp:jingle:1}content')
            if content is not None:
                transport = content.find('{urn:xmpp:jingle:transports:s5b:1}transport')
                if transport is not None:
                    if sid in self.bot.pending_files:
                        peer_dstaddr = transport.get('dstaddr')
                        if peer_dstaddr: self.bot.pending_files[sid]['peer_dstaddr'] = peer_dstaddr

                    # Handle new candidates
                    if transport.findall('{urn:xmpp:jingle:transports:s5b:1}candidate') and not self.bot.pending_files.get(sid, {}).get('s5b_connecting'):
                        self.bot.pending_files[sid]['s5b_connecting'] = True
                        t_key = f"jingle_s5b_info_{sid}"
                        self.bot.pending_files[t_key] = asyncio.create_task(self._socks5_connect_and_save(iq, jingle_sid=sid, task_key=t_key))

                    # Handle candidate-used
                    used = transport.find('{urn:xmpp:jingle:transports:s5b:1}candidate-used')
                    if used is not None:
                        cid = used.get('cid')
                        logging.info(f"JINGLE S5B: Peer is using candidate {cid}")
                        # If peer used our proxy candidate, we must activate it
                        p_jid = next((j for j in self.KNOWN_PROXIES if hashlib.md5(j.encode()).hexdigest() == cid or j == cid), None)
                        if p_jid:
                            asyncio.create_task(self._activate_jingle_proxy(p_jid, sid, iq['from']))

                    # Handle activated
                    activated = transport.find('{urn:xmpp:jingle:transports:s5b:1}activated')
                    if activated is not None:
                        cid = activated.get('cid')
                        logging.info(f"JINGLE S5B: Candidate {cid} activated")
                        if sid in self.bot.pending_files and 's5b_activated_event' in self.bot.pending_files[sid]:
                            self.bot.pending_files[sid]['s5b_activated_event'].set()
            iq.reply().send()
        elif action == 'transport-replace':
            content = jingle.find('{urn:xmpp:jingle:1}content')
            if content is not None:
                ibb_t = content.find('{urn:xmpp:jingle:transports:ibb:1}transport')
                s5b_t = content.find('{urn:xmpp:jingle:transports:s5b:1}transport')
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
                        ET.SubElement(res_c, '{urn:xmpp:jingle:transports:ibb:1}transport', {'sid': ibb_sid})
                        reply.append(res_j); reply.send()
                elif s5b_t is not None:
                    if sid in self.bot.pending_files:
                        s5b_sid = s5b_t.get('sid')
                        self.bot.pending_files[sid]['transport_sid'] = s5b_sid
                        self.bot.pending_files[s5b_sid] = self.bot.pending_files[sid]
                        peer_dstaddr = s5b_t.get('dstaddr')
                        if peer_dstaddr: self.bot.pending_files[sid]['peer_dstaddr'] = peer_dstaddr

                        reply = self.bot.make_iq_set(ito=iq['from'])
                        res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {'action': 'transport-accept', 'sid': sid})
                        res_c = ET.SubElement(res_j, '{urn:xmpp:jingle:1}content', {
                            'creator': content.get('creator'), 'name': content.get('name')
                        })
                        # Jingle S5B: dstaddr = SHA-1(SID + RequesterJID + TargetJID)
                        # Bot is Responder, Bot provides candidates -> Bot is Requester
                        dst_addr = hashlib.sha1(f"{s5b_sid}{self.bot.boundjid.full}{self.bot.pending_files[sid]['initiator']}".encode()).hexdigest()
                        res_t = ET.SubElement(res_c, '{urn:xmpp:jingle:transports:s5b:1}transport', {'sid': s5b_sid, 'mode': 'tcp', 'dstaddr': dst_addr})
                        local_ip = self.get_local_ip()
                        ET.SubElement(res_t, '{urn:xmpp:jingle:transports:s5b:1}candidate',
                                      host=local_ip, port='1080', jid=self.bot.boundjid.full,
                                      cid='direct-host', priority='8253074', type='host')
                        for p_jid, p_info in self.KNOWN_PROXIES.items():
                            ET.SubElement(res_t, '{urn:xmpp:jingle:transports:s5b:1}candidate', host=p_info['host'], port=str(p_info['port']), jid=p_jid, cid=hashlib.md5(p_jid.encode()).hexdigest(), priority='65536', type='proxy')
                        reply.append(res_j); reply.send()
                        if s5b_t.findall('{urn:xmpp:jingle:transports:s5b:1}candidate'):
                            self.bot.pending_files[sid]['s5b_connecting'] = True
                            t_key = f"jingle_s5b_replace_{sid}"
                            self.bot.pending_files[t_key] = asyncio.create_task(self._socks5_connect_and_save(iq, jingle_sid=sid, task_key=t_key))
            iq.reply().send()
        elif action == 'transport-accept':
            iq.reply().send()
        elif action == 'session-terminate':
            if sid in self.bot.pending_files: del self.bot.pending_files[sid]
            iq.reply().send()

    async def _initiate_transport_replace_s5b(self, iq, sid):
        await asyncio.sleep(1)
        file_info = self.bot.pending_files.get(sid)
        if not file_info: return

        s5b_sid = f"s5b_{sid}"
        file_info['transport_sid'] = s5b_sid
        self.bot.pending_files[s5b_sid] = file_info

        # Jingle S5B: dstaddr = SHA-1(SID + RequesterJID + TargetJID)
        # Bot is Requester
        dst_addr = hashlib.sha1(f"{s5b_sid}{self.bot.boundjid.full}{file_info['initiator']}".encode()).hexdigest()

        reply = self.bot.make_iq_set(ito=iq['from'])
        res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {'action': 'transport-replace', 'sid': sid})
        res_c = ET.SubElement(res_j, '{urn:xmpp:jingle:1}content', {
            'creator': file_info.get('content_creator', 'initiator'),
            'name': file_info.get('content_name', 'file')
        })
        res_t = ET.SubElement(res_c, '{urn:xmpp:jingle:transports:s5b:1}transport', {'sid': s5b_sid, 'mode': 'tcp', 'dstaddr': dst_addr})
        local_ip = self.get_local_ip()
        ET.SubElement(res_t, '{urn:xmpp:jingle:transports:s5b:1}candidate',
                      host=local_ip, port='1080', jid=self.bot.boundjid.full,
                      cid='direct-host', priority='8253074', type='host')
        for p_jid, p_info in self.KNOWN_PROXIES.items():
            ET.SubElement(res_t, '{urn:xmpp:jingle:transports:s5b:1}candidate', host=p_info['host'], port=str(p_info['port']), jid=p_jid, cid=hashlib.md5(p_jid.encode()).hexdigest(), priority='65536', type='proxy')
        reply.append(res_j); reply.send()

    def handle_raw_si(self, iq):
        logging.info(f"SI REQUEST from {iq['from']}:\n{ET.tostring(iq.xml, encoding='unicode')}")
        if iq['type'] in ('error', 'result'): return
        if not self.bot.is_allowed(iq['from']):
            reply = iq.error(); reply['error']['condition'] = 'not-authorized'; reply.send(); return
        try:
            si = iq.xml.find('{http://jabber.org/protocol/si}si')
            if si is None: return
            sid, tag = si.get('id'), si.find('{http://jabber.org/protocol/si/profile/file-transfer}file')
            if not sid or tag is None: return
            fname, fsize = os.path.basename(tag.get('name')).replace(' ', '_'), int(tag.get('size', 0))
            user_dir, _ = self.bot.get_user_info(iq['from'])
            if get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                reply = iq.error(); reply['error']['condition'] = 'not-acceptable'; reply.send(); return
            feature_neg = si.find('{http://jabber.org/protocol/feature-neg}feature')
            offered_methods = []
            if feature_neg is None: return
            x_data = feature_neg.find('{jabber:x:data}x')
            if x_data is not None:
                field = next((f for f in x_data.findall('{jabber:x:data}field') if f.get('var') == 'stream-method'), None)
                if field is not None:
                    offered_methods = [v.text for v in field.findall('{jabber:x:data}value')]
                    offered_methods.extend([v.text for v in field.findall('{jabber:x:data}option/{jabber:x:data}value')])
            chosen_method = next((m for m in ['jabber:iq:oob', 'http://jabber.org/protocol/bytestreams', 'http://jabber.org/protocol/ibb'] if m in offered_methods), None)
            if not chosen_method:
                reply = iq.error(); reply['error']['condition'] = 'not-acceptable'; reply.send(); return
            self.bot.pending_files[sid] = {
                'name': fname, 'size': fsize, 'timestamp': asyncio.get_event_loop().time(),
                'ibb_allowed': 'http://jabber.org/protocol/ibb' in offered_methods,
                'peer_jid': iq['from'], 'transport_sid': sid,
                'initiator': iq['from'].full, 'responder': self.bot.boundjid.full
            }
            reply = iq.reply(clear=True)
            res_si = ET.Element('{http://jabber.org/protocol/si}si')
            feature = ET.SubElement(res_si, '{http://jabber.org/protocol/feature-neg}feature')
            x = ET.SubElement(feature, '{jabber:x:data}x', type='submit')
            field = ET.SubElement(x, '{jabber:x:data}field', var='stream-method')
            ET.SubElement(field, '{jabber:x:data}value').text = chosen_method
            reply.append(res_si)
            logging.info(f"SI RESPONSE to {iq['from']}:\n{ET.tostring(reply.xml, encoding='unicode')}")
            reply.send()
        except Exception as e: logging.error(f"SI ERROR: {e}")

    def handle_raw_s5b(self, iq):
        logging.info(f"S5B REQUEST from {iq['from']}:\n{ET.tostring(iq.xml, encoding='unicode')}")
        if iq['type'] in ('error', 'result'): return
        query = iq.xml.find('{http://jabber.org/protocol/bytestreams}query')
        if query is not None and query.find('{http://jabber.org/protocol/bytestreams}streamhost-used') is not None:
             asyncio.create_task(self._socks5_connect_and_save(iq))
        else:
             t_key = f"s5b_{iq['id']}"
             self.bot.pending_files[t_key] = asyncio.create_task(self._socks5_connect_and_save(iq, task_key=t_key))

    async def _activate_jingle_proxy(self, proxy_jid, sid, peer_jid):
        file_info = self.bot.pending_files.get(sid)
        if not file_info: return
        t_sid = file_info.get('transport_sid', sid)
        proxy_info = self.KNOWN_PROXIES.get(proxy_jid)
        if not proxy_info: return

        # Jingle S5B dstaddr = SHA1(SID + InitiatorJID + ResponderJID)
        initiator = file_info.get('initiator')
        responder = file_info.get('responder')
        dst_addr = hashlib.sha1(f"{t_sid}{initiator}{responder}".encode()).hexdigest()

        try:
            # 1. Bot MUST connect to proxy first
            logging.info(f"JINGLE S5B: Connecting to proxy {proxy_jid} ({proxy_info['host']}:{proxy_info['port']})")
            reader, writer = await asyncio.wait_for(asyncio.open_connection(proxy_info['host'], proxy_info['port']), 10)
            writer.write(b"\x05\x01\x00"); await writer.drain()
            if await reader.read(2) != b"\x05\x00":
                logging.error(f"JINGLE S5B: Proxy {proxy_jid} rejected auth"); writer.close(); return

            logging.info(f"JINGLE S5B: Proxy {proxy_jid} SOCKS5 handshake (dstaddr={dst_addr})")
            writer.write(b"\x05\x01\x00\x03" + bytes([len(dst_addr)]) + dst_addr.encode() + b"\x00\x00"); await writer.drain()
            resp = await reader.read(4)
            if not resp or resp[1] != 0x00:
                logging.error(f"JINGLE S5B: Proxy {proxy_jid} rejected connection"); writer.close(); return

            # Read remainder of SOCKS5 response
            atyp = resp[3]
            if atyp == 0x01: await reader.read(6)
            elif atyp == 0x03: addr_len = await reader.read(1); await reader.read(addr_len[0] + 2)
            elif atyp == 0x04: await reader.read(18)

            # 2. Only after successful SOCKS5 connect, send activate IQ to proxy
            logging.info(f"JINGLE S5B: Activating proxy {proxy_jid} for {peer_jid}")
            act_iq = self.bot.make_iq_set(ito=proxy_jid)
            act_q = ET.SubElement(act_iq.xml, '{http://jabber.org/protocol/bytestreams}query', sid=t_sid)
            ET.SubElement(act_q, 'activate').text = peer_jid.full
            await act_iq.send()

            # 3. Send activated notification to peer
            reply = self.bot.make_iq_set(ito=peer_jid)
            res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {'action': 'transport-info', 'sid': sid})
            res_c = ET.SubElement(res_j, '{urn:xmpp:jingle:1}content', {
                'creator': file_info.get('content_creator', 'initiator'),
                'name': file_info.get('content_name', 'file')
            })
            res_t = ET.SubElement(res_c, '{urn:xmpp:jingle:transports:s5b:1}transport', {'sid': t_sid})
            ET.SubElement(res_t, '{urn:xmpp:jingle:transports:s5b:1}activated', cid=hashlib.md5(proxy_jid.encode()).hexdigest())
            reply.append(res_j); reply.send()

            # 4. Start receiving file data
            await self.download_file_task(reader, file_info, peer_jid, sid)
            writer.close(); await writer.wait_closed()
        except Exception as e:
            logging.error(f"JINGLE S5B: Proxy activation/connection failed: {e}")

    async def _socks5_connect_and_save(self, iq, jingle_sid=None, task_key=None):
        sid = None
        try:
            peer_is_requester = True
            if jingle_sid:
                sid = jingle_sid; jingle = iq.xml.find('{urn:xmpp:jingle:1}jingle')
                if jingle is None: return
                content = jingle.find('{urn:xmpp:jingle:1}content')
                if content is None: return
                query = content.find('{urn:xmpp:jingle:transports:s5b:1}transport')
                if query is None: return
                hosts = query.findall('{urn:xmpp:jingle:transports:s5b:1}candidate')
                peer_full = iq['from'].full

                # Sort hosts: proxies first, then public IPs, then private IPs
                hosts.sort(key=lambda h: (0 if h.get('type') == 'proxy' else (2 if self.is_private_ip(h.get('host')) else 1)))
            else:
                query = iq.xml.find('{http://jabber.org/protocol/bytestreams}query')
                if query is None: return
                sid, peer_full = query.get('sid'), iq['from'].full
                used = query.find('{http://jabber.org/protocol/bytestreams}streamhost-used')
                if used is not None:
                    if iq['type'] == 'set':
                        iq.reply().send()
                        jid = used.get('jid'); proxy = self.KNOWN_PROXIES.get(jid)
                        if proxy:
                             hosts = [ET.Element('streamhost', host=proxy['host'], port=str(proxy['port']), jid=jid)]
                             peer_is_requester = False # We offered these, so WE are Requester (must activate)
                        else: return
                    else:
                        jid = used.get('jid'); proxy = self.KNOWN_PROXIES.get(jid)
                        if proxy: hosts = [ET.Element('streamhost', host=proxy['host'], port=str(proxy['port']), jid=jid)]
                        else: reply = iq.error(); reply['error']['condition'] = 'item-not-found'; reply.send(); return
                else:
                    hosts = query.findall('{http://jabber.org/protocol/bytestreams}streamhost')
                    if not hosts:
                        # Peer asks us for candidates
                        reply = iq.reply(clear=True)
                        res_q = ET.Element('{http://jabber.org/protocol/bytestreams}query', {'sid': sid})
                        hosts = []
                        for p_jid, p_info in self.KNOWN_PROXIES.items():
                            sh = ET.SubElement(res_q, '{http://jabber.org/protocol/bytestreams}streamhost', host=p_info['host'], port=str(p_info['port']), jid=p_jid)
                            hosts.append(sh)
                        reply.append(res_q)
                        logging.info(f"S5B CANDIDATES to {iq['from']}:\n{ET.tostring(reply.xml, encoding='unicode')}")
                        reply.send()
                        peer_is_requester = False # We provided these, so WE are Requester

            file_info = self.bot.pending_files.get(sid)
            if not file_info: return
            t_sid = file_info.get('transport_sid', sid)

            # dstaddr calculation
            if jingle_sid:
                # Jingle S5B: dstaddr = SHA-1(SID + InitiatorJID + ResponderJID)
                initiator = file_info.get('initiator')
                responder = file_info.get('responder')
                dst_addr = file_info.get('peer_dstaddr') or hashlib.sha1(f"{t_sid}{initiator}{responder}".encode()).hexdigest()
            else:
                initiator = file_info.get('initiator', peer_full)
                responder = file_info.get('responder', self.bot.boundjid.full)
                dst_addr = hashlib.sha1(f"{t_sid}{initiator}{responder}".encode()).hexdigest()

            if jingle_sid and not hosts:
                jingle = iq.xml.find('{urn:xmpp:jingle:1}jingle')
                if jingle is not None and jingle.get('action') == 'session-initiate':
                    self.bot.pending_files[sid]['s5b_connecting'] = False
                    return

            for host in hosts:
                try:
                    h_host, h_port = host.get('host'), int(host.get('port', 1080))
                    logging.info(f"S5B: Connecting to {h_host}:{h_port} (dst_addr={dst_addr})")
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

                    if jingle_sid:
                        reply = self.bot.make_iq_set(ito=iq['from'])
                        res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {'action': 'transport-info', 'sid': jingle_sid})
                        res_c = ET.SubElement(res_j, '{urn:xmpp:jingle:1}content', {'creator': file_info.get('content_creator', 'initiator'), 'name': file_info.get('content_name', 'file')})
                        res_t = ET.SubElement(res_c, '{urn:xmpp:jingle:transports:s5b:1}transport', {'sid': sid})
                        ET.SubElement(res_t, '{urn:xmpp:jingle:transports:s5b:1}candidate-used', cid=host.get('cid') or host.get('jid'))
                        reply.append(res_j); reply.send()

                        # If proxy, wait for 'activated' stanza from peer
                        if host.get('type') == 'proxy':
                            logging.info(f"JINGLE S5B: Waiting for activated stanza from {iq['from']}")
                            if 's5b_activated_event' not in file_info:
                                file_info['s5b_activated_event'] = asyncio.Event()
                            try:
                                await asyncio.wait_for(file_info['s5b_activated_event'].wait(), 30)
                                logging.info(f"JINGLE S5B: Received activated stanza, proceeding")
                            except asyncio.TimeoutError:
                                logging.error(f"JINGLE S5B: Timeout waiting for activated stanza"); writer.close(); continue
                    else:
                        if iq['type'] == 'get' or (iq['type'] == 'set' and hosts):
                            reply = iq.reply(clear=True)
                            res_q = ET.Element('{http://jabber.org/protocol/bytestreams}query', {'sid': sid})
                            ET.SubElement(res_q, '{http://jabber.org/protocol/bytestreams}streamhost-used', jid=host.get('jid'))
                            reply.append(res_q)
                            logging.info(f"S5B RESULT to {iq['from']}:\n{ET.tostring(reply.xml, encoding='unicode')}")
                            reply.send()

                        # Traditional Proxy Activation
                        if not peer_is_requester and host.get('jid') in self.KNOWN_PROXIES:
                             logging.info(f"S5B: Activating proxy {host.get('jid')} for Peer {peer_full}")
                             act_iq = self.bot.make_iq_set(ito=host.get('jid'))
                             act_q = ET.SubElement(act_iq.xml, '{http://jabber.org/protocol/bytestreams}query', sid=t_sid)
                             ET.SubElement(act_q, 'activate').text = peer_full
                             await act_iq.send()

                    await self.download_file_task(reader, file_info, iq['from'], sid); writer.close(); await writer.wait_closed(); return
                except Exception as e:
                    logging.debug(f"S5B: Connection to {host.get('host')} failed: {e}")
                    continue

            if not jingle_sid and (iq['type'] == 'get' or (iq['type'] == 'set' and hosts)):
                reply = iq.error(); reply['error']['condition'] = 'item-not-found'; reply.send()
            elif jingle_sid and file_info.get('ibb_allowed'):
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
        finally:
            if task_key and task_key in self.bot.pending_files: del self.bot.pending_files[task_key]

    def handle_ibb_stream_request(self, iq):
        sid = iq['ibb_open']['sid']
        file_info = self.bot.pending_files.get(sid)
        if file_info:
             if file_info['peer_jid'].bare == iq['from'].bare:
                 self.bot['xep_0047'].accept_stream(iq)
                 return

    def handle_ibb_stream(self, stream):
        sid = stream.sid
        file_info = self.bot.pending_files.get(sid)
        if file_info:
            if file_info['peer_jid'].bare != stream.peer_jid.bare:
                stream.close(); return
            logging.info(f"IBB stream started for sid={sid}")
            t_key = f"task_{sid}"
            self.bot.pending_files[t_key] = asyncio.create_task(self.download_file_task(stream, file_info, stream.peer_jid, sid, task_key=t_key))
        else: stream.close()

    async def download_file_task(self, reader, file_info, peer_jid, sid, task_key=None):
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
                if file_info.get('jingle'):
                    j_sid = file_info.get('session_sid', sid)
                    ft_ns = file_info.get('ft_ns', 'urn:xmpp:jingle:apps:file-transfer:5')
                    initiator = file_info.get('initiator')

                    reply = self.bot.make_iq_set(ito=peer_jid)
                    res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {
                        'action': 'session-info', 'sid': j_sid,
                        'initiator': initiator, 'responder': self.bot.boundjid.full
                    })
                    ET.SubElement(res_j, f'{{{ft_ns}}}received', {
                        'creator': file_info.get('content_creator', 'initiator'),
                        'name': file_info.get('content_name', 'file')
                    })
                    reply.append(res_j); reply.send()

                    term_iq = self.bot.make_iq_set(ito=peer_jid)
                    res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {
                        'action': 'session-terminate', 'sid': j_sid,
                        'initiator': initiator, 'responder': self.bot.boundjid.full
                    })
                    reason = ET.SubElement(res_j, 'reason')
                    ET.SubElement(reason, 'success')
                    term_iq.append(res_j); term_iq.send()
            else:
                if os.path.exists(path): os.remove(path)
        except Exception as e:
            logging.error(f"DOWNLOAD ERROR: {e}")
            if os.path.exists(path): os.remove(path)
        finally:
            if task_key and task_key in self.bot.pending_files: del self.bot.pending_files[task_key]
            info = self.bot.pending_files.get(sid)
            if info:
                s_sid = info.get('session_sid')
                t_sid = info.get('transport_sid')
                if s_sid and s_sid in self.bot.pending_files: del self.bot.pending_files[s_sid]
                if t_sid and t_sid in self.bot.pending_files: del self.bot.pending_files[t_sid]
            if sid in self.bot.pending_files: del self.bot.pending_files[sid]
