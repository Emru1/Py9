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
        ) -> None:
            self.socket = sock
            self.client_id = client_id
            self.buffer: bytes = b''

        def __receive(self):
            if len(self.buffer) < 4:
                self.buffer += self.socket.recv(4 - len(self.buffer))
            if len(self.buffer) < 4:
                return None

            size = struct.unpack('<I', self.buffer[0:4])[0]
            if len(self.buffer) < size:
                self.buffer += self.socket.recv(size - len(self.buffer))
            if len(self.buffer) < size:
                return None

            operation: self.TRs = self.TRs(struct.unpack('<B', self.buffer[0:1])[0])
            tag: int = struct.unpack('<H', self.buffer[1:3])[0]
            other_data: dict = self._parse_data(operation, self.buffer[3:])

            return {
                'operation': operation,
                'tag': tag,
            } | other_data

        def handle(self):
            data = self.__receive()

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
        new_client: Py9Server.Client = Py9Server.Client(
            self.socket.accept(),
            self.__get_new_client_id(),
        )
        self.selector.register(new_client.socket, selectors.EVENT_READ)
        self.clients[new_client.client_id] = new_client
        return new_client

    def serve(self):
        events = self.selector.select()

        for fd, _ in events:
            if fd == self.socket.fileno():
                self.__accept()
            else:
                self.clients[fd].handle()
