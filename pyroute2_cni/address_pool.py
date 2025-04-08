import random
import socket
import struct


class AddressPool:
    def __init__(self, prefix, size, name):
        self.prefix = struct.pack('BB', *(int(x) for x in prefix.split('.')))
        self.size = size
        self.bits = struct.calcsize(size) * 8
        self.min = 0x1
        self.max = (1 << self.bits) - 1
        self.allocated = set()
        self.name = name
        self.gateway = self.inet_ntoa(self.min)

    def inet_ntoa(self, addr):
        return socket.inet_ntoa(self.prefix + struct.pack('>H', addr))

    def allocate(self):
        while True:
            addr = self.random()
            if addr not in self.allocated:
                self.allocated.add(addr)
                return self.inet_ntoa(addr)

    def random(self):
        return random.randint(self.min + 1, self.max - 1)
