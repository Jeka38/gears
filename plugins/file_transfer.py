import os
import hashlib
import asyncio
import logging
import aiohttp
from slixmpp.xmlstream import ET, matcher, handler
from config import ADMIN_JID, ADMIN_NOTIFY_LEVEL, QUOTA_LIMIT_BYTES
from utils import get_dir_size, safe_quote, get_unique_path
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
        self.bot.register_handler(
            handler.Callback('Jingle', matcher.MatchXPath('{jabber:client}iq/{urn:xmpp:jingle:1}jingle'), self.handle_jingle)
        )
        self.bot.register_handler(
            handler.Callback('OOB', matcher.MatchXPath('{jabber:client}iq/{jabber:iq:oob}query'), self.handle_iq_oob)
        )
        self.bot.add_event_handler("ibb_stream_start", self.handle_ibb_stream)

    def handle_iq_oob(self, iq):
        logging.info(f"IQ OOB REQUEST from {iq['from']}")
        query = iq.xml.find('{jabber:iq:oob}query')
        if query is None: return
        url_tag = query.find('{jabber:iq:oob}url')
        if url_tag is None or not url_tag.text: return
        url = url_tag.text
        desc = query.find('{jabber:iq:oob}desc')
        fname = desc.text if desc is not None and desc.text else os.path.basename(url)
        asyncio.create_task(self.download_from_url(url, fname, iq['from']))
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
                            await loop.run_in_executor(None, f.flush)
                            await loop.run_in_executor(None, os.fsync, f.fileno())

                        real_fname = os.path.basename(path)
                        self.bot.send_message(mto=peer_jid, mbody=f"✅ Готово!\n{self.bot.base_url}/{user_hash}/{safe_quote(real_fname)}", mtype='chat')
                    else:
                        logging.error(f"OOB download failed: HTTP {resp.status}")
        except Exception as e:
            logging.error(f"OOB download error: {e}")
            if os.path.exists(path): os.remove(path)

    def handle_jingle(self, iq):
        jingle = iq.xml.find('{urn:xmpp:jingle:1}jingle')
        if jingle is None: return
        action = jingle.get('action')
        logging.info(f"JINGLE REQUEST ({action}) from {iq['from']}\n{ET.tostring(iq.xml, encoding='unicode')}")
        sid = jingle.get('sid')

        if action == 'session-initiate':
            if not self.bot.is_allowed(iq['from']):
                reply = iq.reply(); reply['type'] = 'error'; reply.send(); return

            content = jingle.find('{urn:xmpp:jingle:1}content')
            if content is None: return

            # Support both FT v4 and v5
            ft_ns = 'urn:xmpp:jingle:apps:file-transfer:5'
            description = content.find(f'{{{ft_ns}}}description')
            if description is None:
                ft_ns = 'urn:xmpp:jingle:apps:file-transfer:4'
                description = content.find(f'{{{ft_ns}}}description')

            if description is None: return
            file_tag = description.find(f'{{{ft_ns}}}file')
            if file_tag is None: return

            name_tag = file_tag.find(f'{{{ft_ns}}}name')
            size_tag = file_tag.find(f'{{{ft_ns}}}size')
            if name_tag is None or size_tag is None: return

            fname = os.path.basename(name_tag.text).replace(' ', '_')
            try: fsize = int(size_tag.text)
            except (ValueError, TypeError): return

            user_dir, _ = self.bot.get_user_info(iq['from'])
            if get_dir_size(user_dir) + fsize > QUOTA_LIMIT_BYTES:
                reply = iq.reply(); reply['type'] = 'error'; reply.send(); return

            # Extract transport SID (important for IBB and S5B)
            transport_sid = sid
            ibb_t = content.find('{urn:xmpp:jingle:transports:ibb:1}transport')
            s5b_t = content.find('{urn:xmpp:jingle:transports:s5b:1}transport')

            if s5b_t is not None and s5b_t.get('sid'):
                transport_sid = s5b_t.get('sid')
            elif ibb_t is not None and ibb_t.get('sid'):
                transport_sid = ibb_t.get('sid')

            self.bot.pending_files[sid] = {
                'name': fname,
                'size': fsize,
                'timestamp': asyncio.get_event_loop().time(),
                'peer_jid': iq['from'],
                'ibb_allowed': True,
                'content_name': content.get('name'),
                'content_creator': content.get('creator'),
                'ft_ns': ft_ns,
                'transport_sid': transport_sid
            }
            if transport_sid != sid:
                self.bot.pending_files[transport_sid] = self.bot.pending_files[sid]

            reply = iq.reply(); reply.send()

            # Respond with session-accept
            try:
                accept_iq = self.bot.make_iq_set(ito=iq['from'])
                res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {'action': 'session-accept', 'sid': sid, 'initiator': iq['from'].full})
                res_c = ET.SubElement(res_j, '{urn:xmpp:jingle:1}content', {'creator': content.get('creator'), 'name': content.get('name')})

                res_d = ET.SubElement(res_c, f'{{{ft_ns}}}description')
                res_f = ET.SubElement(res_d, f'{{{ft_ns}}}file')
                ET.SubElement(res_f, f'{{{ft_ns}}}name').text = fname
                ET.SubElement(res_f, f'{{{ft_ns}}}size').text = str(fsize)

                # Negotiate transport: match what initiator offered
                s5b_t = content.find('{urn:xmpp:jingle:transports:s5b:1}transport')
                ibb_t = content.find('{urn:xmpp:jingle:transports:ibb:1}transport')

                if s5b_t is not None:
                    # Prefer SOCKS5 if offered
                    ET.SubElement(res_c, '{urn:xmpp:jingle:transports:s5b:1}transport', {'sid': transport_sid, 'mode': 'tcp'})
                elif ibb_t is not None:
                    # Fallback to IBB if offered
                    ET.SubElement(res_c, '{urn:xmpp:jingle:transports:ibb:1}transport', {
                        'block-size': ibb_t.get('block-size', '4096'),
                        'sid': transport_sid
                    })
                else:
                    # Default fallback
                    ET.SubElement(res_c, '{urn:xmpp:jingle:transports:ibb:1}transport', {'block-size': '4096', 'sid': sid})

                accept_iq.append(res_j); accept_iq.send()

                # If SOCKS5 candidates were already provided, try to connect
                if s5b_t is not None and s5b_t.findall('{urn:xmpp:jingle:transports:s5b:1}candidate'):
                    asyncio.create_task(self._socks5_connect_and_save(iq, jingle_sid=sid))
            except Exception as e: logging.error(f"Error sending session-accept: {e}")

        elif action == 'transport-info':
            # Handle SOCKS5 candidates if they come
            jingle = iq.xml.find('{urn:xmpp:jingle:1}jingle')
            if jingle is not None:
                content = jingle.find('{urn:xmpp:jingle:1}content')
                if content is not None:
                    transport = content.find('{urn:xmpp:jingle:transports:s5b:1}transport')
                    if transport is not None:
                        asyncio.create_task(self._socks5_connect_and_save(iq, jingle_sid=sid))
            iq.reply().send()

        elif action == 'session-terminate':
            if sid in self.bot.pending_files:
                del self.bot.pending_files[sid]
            iq.reply().send()

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
                    field = None
                    for f in x_data.findall('{jabber:x:data}field'):
                        if f.get('var') == 'stream-method':
                            field = f
                            break
                    if field is not None:
                        # Extract from <value> and <option><value>
                        offered_methods = [v.text for v in field.findall('{jabber:x:data}value')]
                        offered_methods.extend([v.text for v in field.findall('{jabber:x:data}option/{jabber:x:data}value')])

            chosen_method = None
            # Reorder for performance: OOB > SOCKS5 > IBB
            if 'jabber:iq:oob' in offered_methods:
                chosen_method = 'jabber:iq:oob'
            elif 'http://jabber.org/protocol/bytestreams' in offered_methods:
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
                'peer_jid': iq['from'],
                'transport_sid': sid
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
        asyncio.create_task(self._socks5_connect_and_save(iq))

    async def _socks5_connect_and_save(self, iq, jingle_sid=None):
        sid = None
        try:
            if jingle_sid:
                sid = jingle_sid
                jingle = iq.xml.find('{urn:xmpp:jingle:1}jingle')
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
                sid = query.get('sid')
                hosts = query.findall('{http://jabber.org/protocol/bytestreams}streamhost')
                peer_full = iq['from'].full

            file_info = self.bot.pending_files.get(sid)
            if not file_info: return

            dst_addr = hashlib.sha1(f"{sid}{peer_full}{self.bot.boundjid.full}".encode()).hexdigest()

            for host in hosts:
                h_host = host.get('host')
                h_port = int(host.get('port', 1080))
                h_jid = host.get('jid')
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

                    if jingle_sid:
                        # Jingle transport-info candidate-used
                        try:
                            reply = self.bot.make_iq_set(ito=iq['from'])
                            res_j = ET.Element('{urn:xmpp:jingle:1}jingle', {'action': 'transport-info', 'sid': sid})
                            res_c = ET.SubElement(res_j, '{urn:xmpp:jingle:1}content', {
                                'creator': file_info.get('content_creator', 'initiator'),
                                'name': file_info.get('content_name', 'file')
                            })
                            res_t = ET.SubElement(res_c, '{urn:xmpp:jingle:transports:s5b:1}transport', {'sid': sid})
                            ET.SubElement(res_t, 'candidate-used', cid=host.get('cid'))
                            reply.append(res_j); reply.send()
                        except Exception as e: logging.error(f"Error sending transport-info: {e}")
                    else:
                        reply = iq.reply()
                        res_q = ET.Element('{http://jabber.org/protocol/bytestreams}query', {'sid': sid})
                        ET.SubElement(res_q, 'streamhost-used', jid=h_jid)
                        reply.append(res_q); reply.send()

                    await self.download_file_task(reader, file_info, iq['from'], sid)
                    writer.close(); await writer.wait_closed(); return
                except Exception: continue

            if not jingle_sid:
                reply = iq.reply(); reply['type'] = 'error'; reply.send()

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
        path = get_unique_path(os.path.join(user_dir, os.path.basename(file_info['name'])))
        received = 0
        loop = asyncio.get_event_loop()
        try:
            with open(path, 'wb') as f:
                while received < file_info['size']:
                    # IBB reader is IBBytestream, SOCKS5 is asyncio.StreamReader
                    if hasattr(reader, 'recv_queue'):
                        chunk = await reader.recv_queue.get()
                    else:
                        chunk = await reader.read(min(file_info['size'] - received, 1048576))

                    if not chunk: break
                    await loop.run_in_executor(None, f.write, chunk)
                    received += len(chunk)

                await loop.run_in_executor(None, f.flush)
                await loop.run_in_executor(None, os.fsync, f.fileno())

            if received == file_info['size']:
                real_fname = os.path.basename(path)
                self.bot.send_message(mto=peer_jid, mbody=f"✅ Готово!\n{self.bot.base_url}/{user_hash}/{safe_quote(real_fname)}", mtype='chat')
            else:
                if os.path.exists(path): os.remove(path)
        except Exception as e:
            logging.error(f"Ошибка при приёме файла: {e}")
            if os.path.exists(path): os.remove(path)
        finally:
            # Cleanup both session and transport SIDs if they exist
            info = self.bot.pending_files.get(sid)
            if info:
                t_sid = info.get('transport_sid')
                if t_sid and t_sid in self.bot.pending_files:
                    del self.bot.pending_files[t_sid]

            if sid in self.bot.pending_files:
                del self.bot.pending_files[sid]
