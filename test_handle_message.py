
import unittest
from unittest.mock import MagicMock, patch
import os

# Mock dependencies before importing OBBFastBot
with patch('slixmpp.ClientXMPP.__init__', return_value=None), \
     patch('asyncio.create_task', return_value=None):
    from bot import OBBFastBot

class TestHandleMessage(unittest.TestCase):
    def setUp(self):
        with patch('asyncio.create_task', return_value=None):
            self.bot = OBBFastBot('jid', 'pass', 'dir')
        self.bot.db = MagicMock()
        self.bot.boundjid = MagicMock()
        self.bot.boundjid.bare = 'bot@example.com'

        # Mock methods/attributes
        self.bot.is_allowed = MagicMock(return_value=True)
        self.bot.get_user_info = MagicMock(return_value=('user_dir', 'user_hash'))
        self.bot.get_help_text = MagicMock(return_value='Help Text')
        self.bot.send_message = MagicMock()

    @patch('plugins.commands.get_dir_size', return_value=1024)
    @patch('plugins.commands.format_size', side_effect=lambda x: str(x))
    def test_unknown_command_triggers_help(self, mock_format, mock_size):
        msg = {'from': MagicMock(), 'type': 'chat', 'body': 'unknown_cmd'}
        msg['from'].bare = 'user@example.com'
        msg['from'].lower = MagicMock(return_value='user@example.com')

        self.bot.commands.handle_message(msg)

        # Check if send_message was called with help text
        args, kwargs = self.bot.send_message.call_args
        self.assertIn('Help Text', kwargs['mbody'])
        self.assertIn('Квота', kwargs['mbody'])

    def test_known_command_does_not_trigger_extra_help(self):
        msg = {'from': MagicMock(), 'type': 'chat', 'body': 'ping'}
        msg['from'].bare = 'user@example.com'
        msg['from'].lower = MagicMock(return_value='user@example.com')

        self.bot.commands.handle_message(msg)

        # Check if ping response was sent
        self.assertEqual(self.bot.send_message.call_count, 1)
        self.assertEqual(self.bot.send_message.call_args[1]['mbody'], 'pong')

if __name__ == '__main__':
    unittest.main()
