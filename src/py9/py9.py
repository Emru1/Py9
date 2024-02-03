from enum import Enum
from abc import abstractmethod

import selectors
import socket
import struct


class Py9:

    class TRs(Enum):
        Tversion = 100
        Rversion = 101
        Tauth = 102
        Rauth = 103
        Tattach = 104
        Rattach = 105
        Terror = 106  # illegal
        Rerror = 107
        Tflush = 108
        Rflush = 109
        Twalk = 110
        Rwalk = 111
        Topen = 112
        Ropen = 113
        Tcreate = 114
        Rcreate = 115
        Tread = 116
        Rread = 117
        Twrite = 118
        Rwrite = 119
        Tclunk = 120
        Rclunk = 121
        Tremove = 122
        Rremove = 123
        Tstat = 124
        Rstat = 125
        Twstat = 126
        Rwstat = 127

    def __init__(
            self,
            ip: str,
            port: int,
            msize: int = 32768,
    ) -> None:
        self.ip = ip
        self.port = port
        self.selector = selectors.DefaultSelector()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.selector.register(self.socket, selectors.EVENT_READ)

        self.msize = msize

    def _recv_n(
            self,
            sock: socket.socket,
            num: int,
    ) -> bytes:
        assert num > 0

        buffer: bytes = b''
        i: int = 0

        while i < num:
            buffer += sock.recv(num - i)
            i = len(buffer)

        return buffer

    def _recv(
            self,
            sock: socket.socket,
    ) -> dict:
        size: int = struct.unpack("<I", self._recv_n(4))
        buf: bytes = self._recv_n(sock, size - 4)
        operation: self.TRs = self.TRs(int(buf[0]))
        tag: int = struct.unpack("<H", buf[1:3])
        other_data: dict = self._parse_data(operation, buf[3:])

        return {
            'operation': operation,
            'tag': tag,
        } | other_data

    def _parse_data(
            self,
            operation,
            data: bytes,
    ) -> dict:
        ret: dict
        match operation:
            case self.TRs.Tversion:
                ret = {
                    'msize': struct.unpack("<I", data[0:4]),
                    'version': data[4:].decode(),
                }
            case self.TRs.Rversion:
                ret = {
                    'msize': struct.unpack("<I", data[0:4]),
                    'version': data[4:].decode(),
                }
            case self.TRs.Tauth:
                ret = {
                    'afid': struct.unpcak("<I", data[0:4]),
                    
                }
            case self.TRs.Rauth:
                ...
            case self.TRs.Tattach:
                ...
            case self.TRs.Rattach:
                ...
            case self.TRs.Terror:
                raise Exception("There is no Terror code")
            case self.TRs.Rerror:
                ...
            case self.TRs.Tflush:
                ...
            case self.TRs.Rflush:
                ...
            case self.TRs.Twalk:
                ...
            case self.TRs.Rwalk:
                ...
            case self.TRs.Topen:
                ...
            case self.TRs.Ropen:
                ...
            case self.TRs.Tcreate:
                ...
            case self.TRs.Rcreate:
                ...
            case self.TRs.Tread:
                ...
            case self.TRs.Rread:
                ...
            case self.TRs.Twrite:
                ...
            case self.TRs.Rwrite:
                ...
            case self.TRs.Tclunk:
                ...
            case self.TRs.Rclunk:
                ...
            case self.TRs.Tremove:
                ...
            case self.TRs.Rremove:
                ...
            case self.TRs.Tstat:
                ...
            case self.TRs.Rstat:
                ...
            case self.TRs.Twstat:
                ...
            case self.TRs.Rwstat:
                ...
            case _:
                raise Exception("No such operation")
        return ret

    @abstractmethod
    def connect(self):
        ...


class Py9Client(Py9):
    def __init__(
            self,
            ip: str,
            port: int,
            msize: int = 32768,
    ) -> None:
        super().__init__(self, ip, port, msize)
        self.socket.connect((self.ip, self.port))

    def recv(self) -> dict:
        return self._recv(self.socket)
