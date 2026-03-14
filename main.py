import asyncio
import logging
from bot import OBBFastBot
from config import XMPP_JID, XMPP_RESOURCE, XMPP_PASSWORD, DOWNLOAD_DIR, XMPP_HOST, XMPP_PORT

async def main():
    jid = XMPP_JID
    if XMPP_RESOURCE:
        jid = f"{jid}/{XMPP_RESOURCE}"

    bot = OBBFastBot(
        jid,
        XMPP_PASSWORD,
        DOWNLOAD_DIR
    )

    bot.sasl_mechanism = 'SCRAM-SHA-1'
    bot.disabled_sasl_mechanisms = {'DIGEST-MD5', 'SCRAM-SHA-1-PLUS'}
    bot.connect((XMPP_HOST, XMPP_PORT))
    await bot.disconnected

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
