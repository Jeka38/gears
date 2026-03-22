import asyncio
import logging
import unittest
import os
import struct
from unittest.mock import MagicMock, AsyncMock, patch
from slixmpp import JID
from slixmpp.xmlstream import ET
from plugins.file_transfer import FileTransferPlugin, STUN_BINDING_REQUEST, STUN_BINDING_SUCCESS, STUN_MAGIC_COOKIE, STUN_ATTR_XOR_MAPPED_ADDRESS

logging.basicConfig(level=logging.DEBUG)

class MockBot:
    def __init__(self):
        self.boundjid = JID('bot@example.com/res')
        self.pending_files = {}
        self.base_url = 'http://localhost'
        self.db = MagicMock()

    def register_handler(self, handler):
        pass

    def add_event_handler(self, name, handler):
        pass

    def is_allowed(self, jid):
        return True

    def get_user_info(self, jid):
        return '/tmp', 'user_hash'

    def send_message(self, **kwargs):
        print(f"MOCK SEND MESSAGE: {kwargs}")

    def make_iq_set(self, ito=None):
        iq = MagicMock()
        iq.append = MagicMock()
        iq.send = MagicMock()
        return iq

class TestFileTransfer(unittest.IsolatedAsyncioTestCase):
    async def test_si_request(self):
        bot = MockBot()
        plugin = FileTransferPlugin(bot)

        iq = MagicMock()
        iq['from'] = JID('user@example.com/res')
        iq.reply = MagicMock()
        reply = MagicMock()
        iq.reply.return_value = reply
        reply.send = MagicMock()

        si_xml = ET.fromstring("""
        <iq id="7b018157-ebe5-4755-851e-87ae96e9fd1c" to="gears_test@jabberworld.info/bot" type="set">
        <si xmlns="http://jabber.org/protocol/si" id="ft_1573" profile="http://jabber.org/protocol/si/profile/file-transfer">
        <file xmlns="http://jabber.org/protocol/si/profile/file-transfer" name="foo_dr.txt" size="922">
        <range/>
        </file>
        <feature xmlns="http://jabber.org/protocol/feature-neg">
        <x xmlns="jabber:x:data" type="form">
        <field type="list-single" var="stream-method">
        <option>
        <value>http://jabber.org/protocol/bytestreams</value>
        </option>
        <option>
        <value>http://jabber.org/protocol/ibb</value>
        </option>
        </field>
        </x>
        </feature>
        </si>
        </iq>
        """)
        iq.xml = si_xml

        with patch('plugins.file_transfer.get_dir_size', return_value=0):
            plugin.handle_raw_si(iq)

        self.assertIn('ft_1573', bot.pending_files)
        self.assertEqual(bot.pending_files['ft_1573']['name'], 'foo_dr.txt')
        reply.send.assert_called()

    async def test_jingle_ice(self):
        bot = MockBot()
        plugin = FileTransferPlugin(bot)

        iq = MagicMock()
        iq['from'] = JID('user@example.com/res')
        iq.reply = MagicMock()
        reply = MagicMock()
        iq.reply.return_value = reply
        reply.send = MagicMock()

        jingle_xml = ET.fromstring("""
        <jingle xmlns='urn:xmpp:jingle:1'
                action='session-initiate'
                initiator='user@example.com/res'
                sid='sid123'>
          <content creator='initiator' name='file'>
            <description xmlns='urn:xmpp:jingle:apps:file-transfer:5'>
              <file>
                <name>test.txt</name>
                <size>11</size>
              </file>
            </description>
            <transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' ufrag='ufrag1' pwd='pwd1'>
              <candidate component='1' foundation='1' generation='0' id='c1' ip='1.2.3.4' network='1' port='1234' priority='1' protocol='udp' type='host'/>
            </transport>
          </content>
        </jingle>
        """)
        iq.xml = ET.Element('{jabber:client}iq')
        iq.xml.append(jingle_xml)

        with patch('plugins.file_transfer.get_dir_size', return_value=0):
            plugin.handle_jingle(iq)

        await asyncio.sleep(0.5)
        self.assertIn('sid123', bot.pending_files)

        protocol = plugin.active_transfers['sid123']['protocol']
        transport = plugin.active_transfers['sid123']['transport']
        transport.sendto = MagicMock()

        if protocol.f: protocol.f.close()
        mock_file = MagicMock()
        protocol.f = mock_file
        mock_file.fileno.return_value = 1
        protocol.file_path = '/tmp/test.txt'

        trans_id = os.urandom(12)
        stun_request = struct.pack('!HH', STUN_BINDING_REQUEST, 0) + struct.pack('!I', STUN_MAGIC_COOKIE) + trans_id
        protocol.datagram_received(stun_request, ('1.2.3.4', 1234))

        transport.sendto.assert_called()
        protocol.datagram_received(b"hello world", ('1.2.3.4', 1234))
        mock_file.write.assert_called_with(b"hello world")

        self.assertNotIn('sid123', bot.pending_files)

if __name__ == '__main__':
    unittest.main()
