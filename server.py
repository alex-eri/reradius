import asyncio
from libreradius.radius import Server, c, RadiusHandler
import logging


class AuthAll(RadiusHandler):
    async def get_Client(self, message):
        self.log.info('new client %s', message.remote)
        return {'secret': 'testing1234'}

    async def recv_AccessRequest(self, message):
        message.response.code = c.AccessAccept


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    transport = Server(handler=AuthAll, port=1812).start()

    loop = asyncio.get_event_loop()

    try:
        loop.run_forever()
    finally:
        transport.close()
        loop.close()
