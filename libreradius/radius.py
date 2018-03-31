import asyncio
import logging
import struct
import hmac
import hashlib
from . import const as c
from collections import defaultdict
import socket


class MultiDict(defaultdict):
    def __init__(self):
        super().__init__(list)

    def add(self, key, value):
        self[key].append(value)

    def getone(self, key, default=None):
        if self[key]:
            return self[key][0]
        else:
            return default


class Packet(MultiDict):
    body = b''
    ma_cursor = None
    packet_id = 0
    packet_size = 20
    authenticator = b'\0'*16
    secret = b''
    code = 0

    @property
    def header(self):
        return struct.pack(
            "!BBH",
            self.code, self.packet_id, self.packet_size
            ) + self.authenticator

    def get_message_authenticator(self, cursor):
        m = hmac.HMAC(key=self.secret)
        m.update(self.header)
        m.update(self.body[:cursor])
        m.update(bytes(16))
        m.update(self.body[cursor+16:])
        return m.digest()

    def check_ma(self):
        if not self.ma_cursor:
            self.parse()
        assert (self.ma_cursor), "No Message-Authenticator"
        d = self.get_message_authenticator(self.ma_cursor)
        assert d == self.getone(c.MessageAuthenticator), "Message-Authenticator not valid"

    def parse(self):
        cursor = 0
        while cursor < len(self.body):
            key, length = struct.unpack_from('!BB', self.body, cursor)
            cursor += 2
            if key == 26:
                v, t, length = struct.unpack_from('!LBB', self.body, cursor)
                key = (v, t)
                cursor += 6
            length -= 2
            v = self.body[cursor:cursor+length]
            if key == c.MessageAuthenticator:
                self.ma_cursor = cursor
            self.add(key, v)
            cursor += length

    def data(self):
        resp = bytearray(self.header)
        body = bytearray()
        for k, v in self.items():
            if k == c.MessageAuthenticator:
                continue
            v = self.encode(v)
            length = len(v)

            while length > 0:
                if isinstance(k, int):
                    if length > 253:
                        cut = 253
                    else:
                        cut = length
                    key = (k, cut+2)
                elif isinstance(k, tuple):
                    if length > 249:
                        cut = 249
                    else:
                        cut = length
                    key = struct.pack("!BBLBB", 26, cut+8, k[0], k[1], cut+2)

                body.extend(key)
                body.extend(v[:cut])
                v = v[cut:]
                length -= cut

        ma_cursor = 0
        if c.MessageAuthenticator in self.keys() or \
            self.code in (
              c.AccessRequest,
              c.AccessAccept,
              c.AccessReject,
              c.AccessChallenge
        ):
            ma_cursor = len(body)+2
            body.extend((c.MessageAuthenticator, 18))
            body.extend(bytes(16))

        self.packet_size = 20+len(body)
        struct.pack_into("!H", resp, 2, self.packet_size)

        if ma_cursor:
            self.body = body
            self.ma_cursor = ma_cursor

            message_authenticator = self.get_message_authenticator(ma_cursor)
            self[c.MessageAuthenticator] = [message_authenticator]
            body[ma_cursor:ma_cursor+16] = message_authenticator

        resp.extend(body)

        self.authenticator = hashlib.md5(resp+self.secret).digest()
        struct.pack_into("!16s", resp, 4, self.authenticator)


        return bytes(resp)

    def from_raw(self, data):
        header = bytearray(data[:20])
        self.body = data[20:]
        self.code = header[0]
        self.packet_id = header[1]
        self.packet_size = struct.unpack_from('!H', header, 2)[0]
        self.authenticator = header[4:20]
        return self


class Message:
    request = None
    response = None
    control = {}
    remote = ()
    client = {}

    def __init__(self, remote, data):
        self.remote = remote
        self.request = Packet().from_raw(data)
        self.response = Packet()
        self.response.packet_id = self.request.packet_id
        self.response.authenticator = self.request.authenticator


class BaseRadius(asyncio.DatagramProtocol):

    def __init__(self):
        self.log = logging.getLogger('RadiusProtocol')
        super().__init__()

    def connection_made(self, transport):
        """ один конект на все удп """
        self.transport = transport

    def respond_cb(self):
        def untask(task):
            if task.done():
                message = task.result()
                if message and message.response.code:
                    self.respond(message)
                else:
                    self.log.error('No packet for response')
            else:
                self.log.warning('Droped request %s', task.exception())
        return untask

    def respond(self, message):
        self.transport.sendto(message.response.data(), message.remote)

    def send(self, packet, remote):
        self.transport.sendto(packet.data(), remote)

    def error_received(self, exc):
        self.log.error('Error received: %s', exc)

    def connection_lost(self, exc):
        self.log.debug('Stop: %s', exc)

    def datagram_received(self, data, remote):
        self.log.debug('Recieved from %s', remote)
        packet = Message(remote, data)
        f = self.loop.create_task(self.process(packet))
        f.add_done_callback(self.respond_cb())

    async def recv_client(self, message):
        """ check client and set secret for packet """
        client = message.client = await self.get_Client(message)
        assert client and client.get('secret'), "Secret not provided for client"
        if isinstance(client['secret'], str):
            client['secret'] = client['secret'].encode('ascii')
        message.response.secret = message.request.secret = client['secret']
        message.request.check_ma()

    async def process(self, message):
        await self.recv_client(message)

        if message.request.code == c.AccessRequest:
            await self.recv_AccessRequest(message)
        elif message.request.code == c.AccountingRequest:
            await self.recv_AccountingRequest(message)

        if message.response.code not in [2, 3, 5, 11]:
            return
        self.log.debug('Responding to %s', message.remote)
        if message.response.code == c.AccessAccept:
            await self.send_AccessAccept(message)
        elif message.response.code == c.AccessReject:
            await self.send_AccessReject(message)
        elif message.response.code == c.AccessChallenge:
            await self.send_AccessChallenge(message)
        elif message.response.code == c.AccountingResponse:
            await self.send_AccountingResponse(message)

        return message


class RadiusHandler(BaseRadius):
    async def get_Client(self, message):
        return {
            'secret': 'secret'
            }

    async def recv_AccessRequest(self, message):
        pass

    async def recv_AccountingRequest(self, message):
        pass

    async def send_AccessAccept(self, message):
        pass

    async def send_AccessReject(self, message):
        pass

    async def send_AccessChallenge(self, message):
        pass


class Server:
    transport = None
    server = None

    def __init__(self, host="0.0.0.0", port=1812, ttl=64, handler=RadiusHandler):
        self.bind_addr = host, port
        self.ttl = ttl

        assert issubclass(handler, RadiusHandler), "No handler passed"
        self.Handler = handler
        self.Handler.loop = asyncio.get_event_loop()

    def start(self):

        loop = self.Handler.loop
        t = asyncio.Task(loop.create_datagram_endpoint(
            self.Handler, local_addr=self.bind_addr))

        self.transport, self.server = loop.run_until_complete(t)
        self.sock = self.transport.get_extra_info('socket')
        self.sock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
        return self.transport



