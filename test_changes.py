import os
import shutil
from unittest.mock import MagicMock
from plugins.commands import CommandsPlugin
from plugins.file_transfer import FileTransferPlugin
import unittest

class TestBotChanges(unittest.TestCase):
    def setUp(self):
        self.bot = MagicMock()
        async def dummy_coro(*args, **kwargs): pass
        self.bot.file_transfer.download_from_url = MagicMock(side_effect=dummy_coro)
        self.bot.get_user_info.return_value = ('test_dir', 'test_hash')
        self.bot.is_allowed.return_value = True
        self.bot.base_url = 'http://example.com'
        self.bot.get_help_text.return_value = 'help text'
        self.bot.loop = MagicMock()

        if not os.path.exists('test_dir'):
            os.makedirs('test_dir')
        if not os.path.exists('index.php'):
            with open('index.php', 'w') as f:
                f.write('template')

    def tearDown(self):
        if os.path.exists('test_dir'):
            shutil.rmtree('test_dir')

    def test_mv_preserves_extension(self):
        # Create a source file
        src_path = 'test_dir/source.txt'
        with open(src_path, 'w') as f:
            f.write('test')

        cmd_plugin = CommandsPlugin(self.bot)
        msg = MagicMock()
        msg.__getitem__.side_effect = lambda key: {'body': 'mv 1 destination', 'from': MagicMock(), 'type': 'chat'}.get(key)
        msg.xml.find.return_value = None

        # Mock get_all_items to return source.txt
        from plugins import commands
        commands.get_all_items = MagicMock(return_value=['source.txt'])
        commands.resolve_item = MagicMock(side_effect=lambda user_dir, arg, items: os.path.join(user_dir, arg))
        commands.resolve_items_list = MagicMock(return_value=[os.path.abspath(src_path)])
        commands.get_unique_path = MagicMock(side_effect=lambda x: x)

        cmd_plugin.handle_message(msg)

        self.assertTrue(os.path.exists('test_dir/destination.txt'))
        self.assertFalse(os.path.exists('test_dir/source.txt'))

    def test_album_command(self):
        cmd_plugin = CommandsPlugin(self.bot)
        msg = MagicMock()
        msg.__getitem__.side_effect = lambda key: {'body': 'album', 'from': MagicMock(), 'type': 'chat'}.get(key)
        msg.xml.find.return_value = None

        cmd_plugin.handle_message(msg)
        self.assertTrue(os.path.exists('test_dir/index.php'))

    def test_priv_deletes_index_php(self):
        # Create index.php
        with open('test_dir/index.php', 'w') as f:
            f.write('test')

        cmd_plugin = CommandsPlugin(self.bot)
        msg = MagicMock()
        msg.__getitem__.side_effect = lambda key: {'body': 'priv', 'from': MagicMock(), 'type': 'chat'}.get(key)
        msg.xml.find.return_value = None

        cmd_plugin.handle_message(msg)
        self.assertTrue(os.path.exists('test_dir/index.html'))
        self.assertFalse(os.path.exists('test_dir/index.php'))

    def test_pub_deletes_both(self):
        # Create both
        with open('test_dir/index.php', 'w') as f: f.write('test')
        with open('test_dir/index.html', 'w') as f: f.write('test')

        cmd_plugin = CommandsPlugin(self.bot)
        msg = MagicMock()
        msg.__getitem__.side_effect = lambda key: {'body': 'pub', 'from': MagicMock(), 'type': 'chat'}.get(key)
        msg.xml.find.return_value = None

        cmd_plugin.handle_message(msg)
        self.assertFalse(os.path.exists('test_dir/index.html'))
        self.assertFalse(os.path.exists('test_dir/index.php'))

    def test_upload_php_blocking(self):
        ft_plugin = FileTransferPlugin(self.bot)
        peer_jid = 'user@example.com'

        # Test OOB
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        loop.run_until_complete(ft_plugin.download_from_url('http://ex.com/sh.php', 'sh.php', peer_jid))
        self.bot.send_message.assert_called_with(mto=peer_jid, mbody="❌ Ошибка: Загрузка PHP-файлов запрещена!", mtype='chat')

    def test_ls_header(self):
        cmd_plugin = CommandsPlugin(self.bot)
        msg = MagicMock()
        msg.__getitem__.side_effect = lambda key: {'body': 'ls', 'from': MagicMock(), 'type': 'chat'}.get(key)
        msg.xml.find.return_value = None

        from plugins import commands
        commands.get_all_items = MagicMock(return_value=['file1.txt'])

        cmd_plugin.handle_message(msg)

        # Check if reply starts with header
        args, kwargs = self.bot.send_message.call_args
        self.assertTrue(kwargs['mbody'].startswith("Список файлов:"))

    def test_direct_url_download(self):
        cmd_plugin = CommandsPlugin(self.bot)
        msg = MagicMock()
        msg.__getitem__.side_effect = lambda key: {'body': 'https://example.com/image.png', 'from': MagicMock(), 'type': 'chat'}.get(key)
        msg.xml.find.return_value = None

        cmd_plugin.handle_message(msg)
        self.bot.loop.create_task.assert_called_once()

    def test_direct_url_php_blocking(self):
        cmd_plugin = CommandsPlugin(self.bot)
        msg = MagicMock()
        peer_jid = 'user@example.com'
        msg.__getitem__.side_effect = lambda key: {'body': 'https://example.com/shell.php', 'from': peer_jid, 'type': 'chat'}.get(key)
        msg.xml.find.return_value = None

        cmd_plugin.handle_message(msg)
        self.bot.send_message.assert_called_with(mto=peer_jid, mbody="❌ Ошибка: Загрузка PHP-файлов запрещена!", mtype='chat')

if __name__ == '__main__':
    import unittest
    unittest.main()
