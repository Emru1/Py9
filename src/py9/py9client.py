from py9 import Py9
from trs import TRs
from stat9 import Stat

import socket


class Py9Client(Py9):
    def __init__(
            self,
            ip: str,
            port: int,
            msize: int = 32768,
            version: str = "9P2000",
    ) -> None:
        super().__init__(ip, port, msize, version)
        self.is_connected: bool = False

    def connect(self) -> None:
        self.socket.connect((self.ip, self.port))

        data = self.version()

        if data['operation'] != TRs.Rversion:
            raise Exception("Server hasn't responded with Rversion")
        if data['tag'] != 0:
            raise Exception("Server has responded to Tversion with invali tag")
        if data['version'].decode() != self._version:
            raise Exception(
                "Server has responded with version " +
                f"{data['version'].decode()}, expected {self._version}"
            )

        self.is_connected = True

    def version(self) -> dict:
        self.socket.sendall(self._encode_Tversion())
        data: dict = self.recv()
        return data

    def auth(self, afid: int, uname: str, aname: str) -> dict:
        self.socket.sendall(self._encode_Tauth(afid, uname, aname))
        data: dict = self.recv()
        return data

    def flush(self, oldtag: int) -> dict:
        self.socket.sendall(self._encode_Tflush(oldtag))
        data: dict = self.recv()
        return data

    def attach(self) -> dict:
        self.socket.sendall(self._encode_Tattach())
        data: dict = self.recv()
        return data

    def walk(self, fid: int, newfid: int, names: list[str]) -> dict:
        self.socket.sendall(self._encode_Twalk(fid, newfid, names))
        data: dict = self.recv()
        return data

    def open(self, fid: int, mode: int) -> dict:
        self.socket.sendall(self._encode_Topen(fid, mode))
        data: dict = self.recv()
        return data

    def create(self, fid: int, name: str, perm: int, mode: int) -> dict:
        raise NotImplementedError

    def read(self, fid: int, offset: int, count: int) -> dict:
        self.socket.sendall(self._encode_Tread(fid, offset, count))
        data: dict = self.recv()
        return data

    def write(self, fid: int, offset: int, data: bytes) -> dict:
        self.socket.sendall(self._encode_Twrite(fid, offset, data))
        data: dict = self.recv()
        return data

    def clunk(self, fid: int) -> dict:
        self.socket.sendall(self._encode_Tclunk(fid))
        data: dict = self.recv()
        return data

    def remove(self, fid: int) -> dict:
        self.socket.sendall(self._encode_Tremove(fid))
        data: dict = self.recv()
        return data

    def stat(self, fid: int) -> dict:
        self.socket.sendall(self._encode_Tstat(fid))
        data: dict = self.recv()
        return data

    def wstat(self, fid: int, stat: Stat) -> dict:
        self.socket.sendall(self._encode_Twstat(fid, stat))
        data: dict = self.recv()
        return data

    def recv(self) -> dict:
        return self._recv(self.socket)

    def read_dir(self, fid: int, offset: int, count: int) -> list[Stat]:
        self.socket.sendall(self._encode_Tread(fid, offset, count))
        pkt: dict = self.recv()
        data = pkt['data']

        stats: list[Stat] = []
        offset = 0

        while offset < len(data):
            stat = Stat.from_bytes(data[offset:])
            offset += stat.size + 2
            stats.append(stat)
        return stats

    def __del__(self) -> None:
        if self.is_connected:
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.recv(0)
            self.socket.close()
