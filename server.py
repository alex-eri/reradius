import asyncio
from libreradius.radius import Server, c, RadiusHandler
from libreradius.dictionary import Dictionary
import logging

# Example server accepts all requests sended with secret 'testing1234'
# on port 1812 and answers Access-Accept for password "password"


class AuthPAP(RadiusHandler):
    def __init__(self):
        self.dict = Dictionary().load('/usr/share/freeradius/dictionary')
        super().__init__()

    async def get_Client(self, message):
        self.log.info('new client %s', message.remote)
        return {'secret': 'testing1234'}

    async def recv_AccessRequest(self, message):
        passw = self.dict.decode(message.request, 'User-Password')
        self.log.info(passw)
        if passw == 'password':
            message.response.code = c.AccessAccept
        else:
            message.response.code = c.AccessReject


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    transport = Server(handler=AuthPAP, port=1812).start()
    loop = asyncio.get_event_loop()
    try:
        loop.run_forever()
    finally:
        transport.close()
        loop.close()
