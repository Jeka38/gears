import os
import logging
from config import ADMIN_JID, STATUS_MESSAGE
from .base import BasePlugin

class PresencePlugin(BasePlugin):
    def __init__(self, bot):
        super().__init__(bot)
        self.bot.add_event_handler("session_start", self.start)
        self.bot.add_event_handler("presence_subscribe", self.handle_presence_subscribe)
        self.bot.add_event_handler("presence_subscribed", self.handle_presence_subscribed)
        self.bot.add_event_handler("presence_unsubscribe", self.handle_presence_unsubscribe)
        self.bot.add_event_handler("presence_unsubscribed", self.handle_presence_unsubscribed)

    async def start(self, event):
        self.bot['xep_0030'].add_feature('http://jabber.org/protocol/si')
        self.bot['xep_0030'].add_feature('http://jabber.org/protocol/bytestreams')
        self.bot['xep_0030'].add_feature('http://jabber.org/protocol/ibb')
        self.bot['xep_0030'].add_feature('http://jabber.org/protocol/si/profile/file-transfer')
        self.bot['xep_0030'].add_feature('urn:xmpp:jingle:1')
        self.bot['xep_0030'].add_feature('urn:xmpp:jingle:apps:file-transfer:4')
        self.bot['xep_0030'].add_feature('urn:xmpp:jingle:apps:file-transfer:5')
        self.bot['xep_0030'].add_feature('urn:xmpp:jingle:transports:s5b:1')
        self.bot['xep_0030'].add_feature('urn:xmpp:jingle:transports:ibb:1')
        self.bot['xep_0030'].add_feature('urn:xmpp:jingle:transports:ice-udp:1')
        self.bot['xep_0030'].add_feature('urn:xmpp:jingle:transports:ice:0')
        self.bot['xep_0030'].add_feature('jabber:iq:oob')
        self.bot['xep_0030'].add_feature('jabber:x:oob')
        self.bot['xep_0030'].add_feature('urn:xmpp:bob')
        self.bot.send_presence(pstatus=STATUS_MESSAGE)
        await self.bot.get_roster()
        logging.info(f"✅ БОТ ЗАПУЩЕН: {self.bot.boundjid}")

    def handle_presence_subscribe(self, presence):
        jid = presence['from'].bare
        logging.info(f"🆕 Запрос подписки от {jid}")
        if not self.bot.is_allowed(presence['from']):
            logging.info(f"ACCESS DENIED (subscribe) from {jid}")
            self.bot.send_message(mto=jid,
                                  mbody=f"⚠️ Доступ запрещён. Пожалуйста, обратитесь к администратору для получения доступа: {ADMIN_JID}",
                                  mtype='chat')
            return
        self.bot.send_presence(pto=jid, ptype='subscribed')
        self.bot.send_presence(pto=jid, ptype='subscribe')
        is_admin = ADMIN_JID and jid == ADMIN_JID.lower()
        _, user_hash = self.bot.get_user_info(presence['from'])
        welcome_msg = f"Добро пожаловать!\nЯ бот для быстрой передачи файлов.\n\n{self.bot.get_help_text(is_admin, user_hash)}"
        self.bot.send_message(mto=jid, mbody=welcome_msg, mtype='chat')

    def handle_presence_subscribed(self, presence):
        jid = presence['from'].bare
        logging.info(f"✅ Подписка подтверждена от {jid}")
        if ADMIN_JID:
            self.bot.send_message(mto=ADMIN_JID, mbody=f"✅ Пользователь {jid} добавил бота в контакты", mtype='chat')

    def handle_presence_unsubscribe(self, presence):
        jid = presence['from'].bare
        logging.info(f"➖ Запрос отписки от {jid}")
        if ADMIN_JID:
            self.bot.send_message(mto=ADMIN_JID, mbody=f"➖ Пользователь {jid} удалил бота из контактов", mtype='chat')

    def handle_presence_unsubscribed(self, presence):
        jid = presence['from'].bare
        logging.info(f"❌ Подписка отменена от {jid}")
