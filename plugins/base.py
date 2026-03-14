class BasePlugin:
    def __init__(self, bot):
        self.bot = bot
        self.db = bot.db

    def reply(self, msg, text):
        self.bot.send_message(mto=msg['from'], mbody=text, mtype='chat')
