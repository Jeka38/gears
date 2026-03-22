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

    def is_private_ip(self, ip):
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except: return True

    async def discover_proxies(self):
        logging.info("SOCKS5 Proxy Discovery started")
        try:
            # Check server domain and its items
            targets = [self.bot.boundjid.domain]
            try:
                items = await self.bot['xep_0030'].get_items(jid=self.bot.boundjid.domain)
                targets.extend([item['jid'] for item in items['disco_items']])
            except: pass

            for target_jid in targets:
                try:
                    # Step 2: Query info for each item
                    info = await self.bot['xep_0030'].get_info(jid=target_jid)
                    # Step 3: Check for SOCKS5 bytestreams feature
                    features = info.xml.find('{http://jabber.org/protocol/disco#info}query').findall('{http://jabber.org/protocol/disco#info}feature')
                    if any(f.get('var') == 'http://jabber.org/protocol/bytestreams' for f in features):
                        # Step 4: Query the proxy for its host/port
                        iq = self.bot.make_iq_get(ito=target_jid)
                        iq.append(ET.Element('{http://jabber.org/protocol/bytestreams}query'))
                        res = await iq.send()
                        query = res.xml.find('{http://jabber.org/protocol/bytestreams}query')
                        if query is not None:
                            for streamhost in query.findall('{http://jabber.org/protocol/bytestreams}streamhost'):
                                host, port = streamhost.get('host'), streamhost.get('port', '1080')
                                self.proxies[target_jid] = {'host': host, 'port': port}
                                logging.info(f"DISCOVERED PROXY: {target_jid} -> {host}:{port}")
                except Exception as e:
                    logging.debug(f"Disco info failed for {target_jid}: {e}")

            # Add fallback known proxies if none discovered
            if not self.proxies:
                 self.proxies = {
                    'proxy.eu.jabber.network': {'host': 'proxy.eu.jabber.network', 'port': '1080'},
                    'proxy.jabber.ru': {'host': 'proxy.jabber.ru', 'port': '1080'},
                 }
                 logging.info("No proxies discovered, using fallbacks")
        except Exception as e:
            logging.error(f"Proxy discovery error: {e}")

    def __init__(self, bot):
        super().__init__(bot)
        self.proxies = {}
        self.bot.register_handler(
            handler.Callback('Jingle', matcher.MatchXPath('{jabber:client}iq/{urn:xmpp:jingle:1}jingle'), self.handle_jingle)
        )
        self.bot.register_handler(
            handler.Callback('OOB', matcher.MatchXPath('{jabber:client}iq/{jabber:iq:oob}query'), self.handle_iq_oob)
        )
        self.bot.add_event_handler("ibb_stream_start", self.handle_ibb_stream)
        self.bot.add_event_handler("ibb_stream_request", self.handle_ibb_stream_request)

    def handle_ibb_stream_request(self, iq):
        if iq['type'] in ('error', 'result'): return
        sid = iq.xml.find('{http://jabber.org/protocol/ibb}open').get('sid')
        peer_jid = iq['from']

        # Exact match
        if sid in self.bot.pending_files:
            logging.info(f"IBB exact match found for sid={sid}")
            self.bot['xep_0047'].accept_stream(iq)
            return

        # Lenient match by peer JID
        found_sid = None
        newest_time = 0
        for s, info in self.bot.pending_files.items():
            if isinstance(info, dict) and info.get('peer_jid') and info['peer_jid'].bare == peer_jid.bare:
                if info.get('timestamp', 0) > newest_time:
                    newest_time = info['timestamp']
                    found_sid = s

        if found_sid:
            logging.info(f"IBB lenient match found for peer={peer_jid.bare}, mapping {sid} to {found_sid}")
            self.bot.pending_files[sid] = self.bot.pending_files[found_sid]
            self.bot['xep_0047'].accept_stream(iq)
        else:
            logging.warning(f"IBB request REJECTED: no pending session for {peer_jid.bare} (sid={sid})")
            reply = iq.error()
            reply['error']['condition'] = 'item-not-found'
            reply.send()

    def handle_iq_oob(self, iq):
        if iq['type'] in ('error', 'result'): return
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

    def handle_jingle(self, iq):
        if iq['type'] in ('error', 'result'): return
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
            ibb_t, s5b_t = content.find('{urn:xmpp:jingle:transports:ibb:1}transport'), content.find('{urn:xmpp:jingle:transports:s5b:1}transport')
            if s5b_t is not None and s5b_t.get('sid'): transport_sid = s5b_t.get('sid')
            elif ibb_t is not None and ibb_t.get('sid'): transport_sid = ibb_t.get('sid')
            else: transport_sid = sid
            self.bot.pending_files[sid] = {
                'name': fname, 'size': fsize, 'timestamp': asyncio.get_event_loop().time(),
                'peer_jid': iq['from'], 'ibb_allowed': True,
                'content_name': content.get('name'), 'content_creator': content.get('creator'),
                'ft_ns': ft_ns, 'session_sid': sid, 'transport_sid': transport_sid, 's5b_connecting': False,
                'my_candidates': []
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
                    for p_jid, p_info in self.proxies.items():
                        cid = hashlib.md5(p_jid.encode()).hexdigest()
                        host_info = {'host': p_info['host'], 'port': str(p_info.get('port', 1080)), 'jid': p_jid, 'cid': cid, 'type': 'proxy'}
                        self.bot.pending_files[sid]['my_candidates'].append(host_info)
                        ET.SubElement(res_t, '{urn:xmpp:jingle:transports:s5b:1}candidate',
                                      host=host_info['host'], port=host_info['port'],
                                      jid=host_info['jid'], cid=host_info['cid'],
                                      priority='65536', type='proxy')
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


    async def _socks5_connect_and_save(self, iq, sid):
        try:
            file_info = self.bot.pending_files.get(sid)
            if not file_info: return

            jingle = iq.xml.find('{urn:xmpp:jingle:1}jingle')
            if jingle is None: return
            content = jingle.find('{urn:xmpp:jingle:1}content')
            if content is None: return
            query = content.find('{urn:xmpp:jingle:transports:s5b:1}transport')
            if query is None: return
            peer_full = iq['from'].full
            used = query.find('{urn:xmpp:jingle:transports:s5b:1}candidate-used')

            if used is not None:
                cid = used.get('cid')
                candidate = next((c for c in query.findall('{urn:xmpp:jingle:transports:s5b:1}candidate') if c.get('cid') == cid), None)
                if candidate is None:
                    # Check our own candidates if it's one we offered
                    my_c = next((c for c in file_info.get('my_candidates', []) if c.get('cid') == cid), None)
                    if my_c:
                        candidate = ET.Element('candidate', my_c)

                if candidate is not None:
                    hosts = [candidate]
                else: hosts = []
            else:
                hosts = query.findall('{urn:xmpp:jingle:transports:s5b:1}candidate')
            t_sid = file_info.get('transport_sid', sid)
            dst_addr = hashlib.sha1(f"{t_sid}{peer_full}{self.bot.boundjid.full}".encode()).hexdigest()

            if not hosts:
                # If we are the responder and this is session-initiate, just return.
                # Initiator will send transport-info later with its candidates.
                jingle = iq.xml.find('{urn:xmpp:jingle:1}jingle')
                if jingle is not None and jingle.get('action') == 'session-initiate':
                    self.bot.pending_files[sid]['s5b_connecting'] = False
                    return

            # Sort hosts: proxies first, then public IPs, then private IPs
            def host_priority(h):
                h_type = h.get('type', 'host')
                h_ip = h.get('host')
                if h_type == 'proxy': return 0
                if not self.is_private_ip(h_ip): return 1
                return 2

            hosts = sorted(hosts, key=host_priority)

            for host in hosts:
                try:
                    h_jid = host.get('jid')
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

                    # Proxy Activation (XEP-0065)
                    # Use bare JID for matching discovered proxies or check Jingle my_candidates
                    is_my_proxy = h_jid and (h_jid.bare in self.proxies or h_jid.full in self.proxies)
                    if not is_my_proxy:
                        is_my_proxy = any(c.get('jid') == h_jid for c in file_info.get('my_candidates', []))

                    if is_my_proxy:
                        logging.info(f"Activating SOCKS5 proxy: {h_jid}")
                        act_iq = self.bot.make_iq_set(ito=h_jid)
                        query_act = ET.SubElement(act_iq.xml, '{http://jabber.org/protocol/bytestreams}query', {'sid': t_sid})
                        ET.SubElement(query_act, 'activate').text = peer_full
                        await act_iq.send()

                    reply = self.bot.make_iq_set(ito=iq['from'])
                    res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {
                        'action': 'transport-info',
                        'sid': sid,
                        'initiator': peer_full
                    })
                    res_c = ET.SubElement(res_j, '{urn:xmpp:jingle:1}content', {
                        'creator': file_info.get('content_creator', 'initiator'),
                        'name': file_info.get('content_name', 'file')
                    })
                    res_t = ET.SubElement(res_c, '{urn:xmpp:jingle:transports:s5b:1}transport', {'sid': t_sid})
                    ET.SubElement(res_t, '{urn:xmpp:jingle:transports:s5b:1}candidate-used', cid=host.get('cid'))
                    reply.append(res_j); reply.send()
                    await self.download_file_task(reader, file_info, iq['from'], sid); writer.close(); await writer.wait_closed(); return
                except Exception: continue
            if file_info.get('ibb_allowed'):
                logging.info(f"SOCKS5 failed for Jingle sid={sid}, falling back to IBB")
                new_ibb_sid = f"fallback_{sid}"
                self.bot.pending_files[sid]['transport_sid'] = new_ibb_sid
                self.bot.pending_files[new_ibb_sid] = self.bot.pending_files[sid]

                reply = self.bot.make_iq_set(ito=iq['from'])
                res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {
                    'action': 'transport-replace',
                    'sid': sid,
                    'initiator': iq['from'].full
                })
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
                if 'session_sid' in file_info:
                    # Jingle success signaling
                    s_sid, ft_ns = file_info['session_sid'], file_info.get('ft_ns', 'urn:xmpp:jingle:apps:file-transfer:5')

                    # session-info (received)
                    info_iq = self.bot.make_iq_set(ito=peer_jid)
                    res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {
                        'action': 'session-info',
                        'sid': s_sid,
                        'initiator': peer_jid.full
                    })
                    ET.SubElement(res_j, f'{{{ft_ns}}}received', {'xmlns': ft_ns})
                    info_iq.append(res_j); info_iq.send()

                    # session-terminate (success)
                    term_iq = self.bot.make_iq_set(ito=peer_jid)
                    res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {
                        'action': 'session-terminate',
                        'sid': s_sid,
                        'initiator': peer_jid.full
                    })
                    reason = ET.SubElement(res_j, '{urn:xmpp:jingle:1}reason')
                    ET.SubElement(reason, '{urn:xmpp:jingle:1}success')
                    term_iq.append(res_j); term_iq.send()
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
