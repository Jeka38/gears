import asyncio
import logging
import unittest
import os
import struct
import socket
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

class TestJingleICE(unittest.IsolatedAsyncioTestCase):
    async def test_session_initiate_with_stun(self):
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
        reply.send.assert_called()
        self.assertIn('sid123', plugin.active_transfers)

        protocol = plugin.active_transfers['sid123']['protocol']
        transport = plugin.active_transfers['sid123']['transport']
        transport.sendto = MagicMock()

        # Mock protocol file
        if protocol.f: protocol.f.close()
        mock_file = MagicMock()
        protocol.f = mock_file
        mock_file.fileno.return_value = 1
        protocol.file_path = '/tmp/test.txt'

        # 1. Send STUN Binding Request
        trans_id = os.urandom(12)
        stun_request = struct.pack('!HH', STUN_BINDING_REQUEST, 0) + struct.pack('!I', STUN_MAGIC_COOKIE) + trans_id
        protocol.datagram_received(stun_request, ('1.2.3.4', 1234))

        # Verify STUN Binding Success was sent
        transport.sendto.assert_called()
        response_data = transport.sendto.call_args[0][0]
        self.assertEqual(struct.unpack('!H', response_data[:2])[0], STUN_BINDING_SUCCESS)
        self.assertEqual(response_data[8:20], trans_id)

        # Verify XOR-MAPPED-ADDRESS
        self.assertIn(struct.pack('!H', STUN_ATTR_XOR_MAPPED_ADDRESS), response_data)

        # Verify STUN request was NOT written to file
        mock_file.write.assert_not_called()

        # 2. Send real data from correct address
        protocol.datagram_received(b"hello world", ('1.2.3.4', 1234))

        # Verify data WAS written to file
        mock_file.write.assert_called_with(b"hello world")

        # 3. Send real data from WRONG address
        mock_file.write.reset_mock()
        protocol.datagram_received(b"evil data", ('6.6.6.6', 666))
        mock_file.write.assert_not_called()

        # Verify cleanup
        self.assertNotIn('sid123', bot.pending_files)
        self.assertNotIn('sid123', plugin.active_transfers)

if __name__ == '__main__':
    unittest.main()
