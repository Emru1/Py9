from py9 import Py9

import socket
import selectors
import struct


class Py9Server(Py9):
    class Client(Py9):
        def __init__(
                self,
                sock: socket.socket,
                client_id: int,
                msize: int = 32768,
                version: str = "9P2000",
        ) -> None:
            self.socket = sock
            self.client_id = client_id
            self.msize = msize
            self._version: str = version
            self.buffer: bytes = b''

            self.tag: int = -1

        def receive(self):
            if len(self.buffer) < 4:
                self.buffer += self.socket.recv(4 - len(self.buffer))
            if len(self.buffer) < 4:
                return None

            size = struct.unpack('<I', self.buffer[0:4])[0]
            if len(self.buffer) < size:
                self.buffer += self.socket.recv(size - len(self.buffer))
            if len(self.buffer) < size:
                return None

            operation: self.TRs = self.TRs(
                struct.unpack('<B', self.buffer[4:5])[0])
            tag: int = struct.unpack('<H', self.buffer[5:7])[0]
            other_data: dict = self._parse_data(operation, self.buffer[7:])

            self.buffer = b''

            return {
                'operation': operation,
                'tag': tag,
            } | other_data

    def __init__(
            self,
            ip: str,
            port: int,
            msize: int = 32768,
            version: str = "9P2000",
    ) -> None:
        super().__init__(ip, port, msize, version)
        self.clients: dict[int, Py9Server.Client] = {}
        self.client_id: int = 0
        self.socket.bind((ip, port))
        self.socket.listen(10)

    def __get_new_client_id(self) -> int:
        self.client_id += 1
        return self.client_id

    def __accept(self) -> Client:
        sock, _ = self.socket.accept()
        cid = self.__get_new_client_id()
        new_client: Py9Server.Client = Py9Server.Client(
            sock,
            cid,
        )
        self.clients[sock.fileno()] = new_client
        self.selector.register(sock, selectors.EVENT_READ)
        return new_client

    def serve(self):
        ret: list[dict] = []
        events = self.selector.select()

        for key, _ in events:
            if key.fd == self.socket.fileno():
                self.__accept()
            else:
                client: Py9Server.Client = self.clients[key.fd]
                data = client.receive()
                if data:
                    ret.append({
                        'client_id': key.fd,
                        'data': data,
                        'operation': data['operation'],
                    })

        for packet in ret:
            match packet['operation']:
                case self.TRs.Tversion:
                    self.handle_Tversion(packet)
                case self.TRs.Tattach:
                    self.handle_Tattach(packet)
        return ret

    def handle_Tversion(self, d: dict):
        client = self.clients[d['client_id']]
        data = d['data']

        client.socket.sendall(client._encode_Rversion(data['tag']))

    def handle_Tattach(self, d: dict):
        client = self.clients[d['client_id']]
        data = d['data']

        print(d)

    def __del__(self):
        clients = list(self.clients.keys())
        for id in clients:
            self.selector.unregister(self.clients[id].socket)
            del self.clients[id]

        super().__del__()
