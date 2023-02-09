from pymem import Pymem
from pymem.pattern import pattern_scan_all
import regex


class Memory():
    def __init__(self, mem: Pymem) -> None:
        self.mem = mem
        self.active = False

    def get_add(self, modname, pattern) -> list:
        addresses = pattern_scan_all(self.mem.process_handle, pattern)
        return addresses

    def convert_pattern_to_bytes(self, string: str):
        string = str.join(" ", string.splitlines())
        bytes_list = string.split(' ')
        final = bytearray()
        for byte in bytes_list:
            if byte == "??":
                final += bytes('.', 'utf-8')
            else:
                byte = bytes.fromhex(byte)
                try:
                    chr(byte)
                except:
                    final += regex.escape(byte)
                else:
                    final += byte   

        return bytes(final)

    def getPtrAddress(self, addr, offsets):
        for i in offsets[:-1]:
            addr = self.mem.read_int(addr + i)
        addr =  addr + offsets[-1]
        return addr