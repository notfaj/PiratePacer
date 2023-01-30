from pymem import Pymem
from wizwalker.utils import XYZ
from icecream import ic
import time

pog_pattern ='''10 ea 05 02 ?? ?? ?? ?? ?? ?? ?? ??
                00 00 00 00 00 00 00 00 00 ?? ?? ??
                00 00 00 00 00 00 00 00 00 00 00 00
                ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00'''

real_z_pattern = '''?? ?? ?? 14 ?? ?? ?? ?? ?? ?? ?? 14 ?? ?? ?? ?? ?? ?? ?? 14 ??
                    ?? ?? ?? ?? ?? ?? 14 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
                    ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
                    ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 ??
                    02 ?? ?? ?? ?? 00 00 00 00 55 da ba ?? ?? ?? ?? ?? ?? ?? 12 ??
                    ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 ?? ??
                    ?? 00 00 00 00 0f 00 00 00 00 00 00 00'''

quest_pattern = '''?? ?? ?? ?? ?? ?? df ?? ?? fc ?? 2a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2a ?? ?? ?? ?? ?? ?? ?? ??'''

class Memory():
    def __init__(self) -> None:
        self.mem: Pymem

    def get_add(self, modname, pattern) -> list:
        module = module_from_name(self.mem.process_handle, modname)
        addresses = pymem.pattern.pattern_scan_all(self.mem.process_handle, pattern, return_multiple=True)
        return addresses
    
    def convert_pattern_to_bytes(self, string: str):
        string = str.join(" ", string.splitlines())
        bytes_list = string.split(' ')
        final = bytearray()
        for byte in bytes_list:
            if byte == "??":
                final += bytes('.', 'utf-8')
            else:
                final += bytes.fromhex(byte)
        return bytes(final)

    def getPtrAddress(self, addr, offsets):
        for i in offsets[:-1]:
            addr = self.mem.read_int(addr + i)
        addr =  addr + offsets[-1]
        return addr


class Cam(Memory):
    def __init__(self, mem: Pymem) -> None:
        self.mem = mem
        self.topAddress = self.find_base()
        self.BaseAddress: int
        self.offsets = [0x90, 0x00, 0x08, 0x180]
    
    def find_base(self) -> int:
        self.topAddress = self.get_add("Pirate.exe", self.convert_pattern_to_bytes(pog_pattern))[0]
        return self.topAddress
    
    def read_xyz(self):
        try:
            self.BaseAddress = self.getPtrAddress(self.topAddress, self.offsets)
            self.xyz = XYZ(self.mem.read_float(self.BaseAddress - 0x8), self.mem.read_float(self.BaseAddress - 0x4), self.mem.read_float(self.BaseAddress))
        except pymem.exception.MemoryReadError:
            time.sleep(0.5) # if it fails blame slack
            self.read_xyz() #please olaf and starr don't yell at me :c
            
        return self.xyz
        
    def write_xyz(self, xyz: XYZ) -> None:
        self.BaseAddress = self.getPtrAddress(self.topAddress, self.offsets)
        self.mem.write_float(self.BaseAddress - 0x8, xyz.x )
        self.mem.write_float(self.BaseAddress - 0x4, xyz.y)
        self.mem.write_float(self.BaseAddress, xyz.z)


class PlayerModel(Memory):
    def __init__(self, mem: Pymem) -> None:
        self.mem = mem
        self.topAddress = self.find_base()
        self.BaseAddress: int
        self.offsets = [0x98, 0x114, 0x00, 0x08, 0x00, 0x5C]

    def find_base(self) -> int:
        self.topAddress = self.get_add("Pirate.exe", self.convert_pattern_to_bytes(pog_pattern))[0]
        return self.topAddress

    def read_xyz(self):
        try:
            self.BaseAddress = self.getPtrAddress(self.topAddress, self.offsets)
            self.xyz = XYZ(self.mem.read_float(self.BaseAddress - 8), self.mem.read_float(self.BaseAddress - 4), self.mem.read_float(self.BaseAddress))
        except pymem.exception.MemoryReadError:
            time.sleep(0.5) # if it fails blame slack
            self.read_xyz() #please olaf and starr don't yell at me :c
        return self.xyz

    def write_xyz(self, xyz: XYZ) -> None:
        self.BaseAddress = self.getPtrAddress(self.topAddress, self.offsets)
        self.mem.write_float(self.BaseAddress - 0x8, xyz.x )
        self.mem.write_float(self.BaseAddress - 0x4, xyz.y)
        self.mem.write_float(self.BaseAddress, xyz.z)

class Player(Memory):
    def __init__(self, mem: Pymem) -> None:
        self.mem = mem
        self.topAddress = self.find_base()
        self.BaseAddress: int
        self.offsets = [0x10, 0x8, 0x74, 0x24, 0x48]

    def find_base(self) -> int:
        self.topAddress = self.get_add("Pirate.exe", self.convert_pattern_to_bytes(real_z_pattern))[0]
        return self.topAddress

    def read_xyz(self):
        try:
            self.BaseAddress = self.getPtrAddress(self.topAddress, self.offsets)
            self.xyz = XYZ(self.mem.read_float(self.BaseAddress - 8), self.mem.read_float(self.BaseAddress - 4), self.mem.read_float(self.BaseAddress))
        except pymem.exception.MemoryReadError:
            time.sleep(0.5) # if it fails blame slack
            self.read_xyz() #please olaf and starr don't yell at me :c
        return self.xyz

    def write_xyz(self, xyz: XYZ) -> None:
        self.BaseAddress = self.getPtrAddress(self.topAddress, self.offsets)
        self.mem.write_float(self.BaseAddress - 0x8, xyz.x )
        self.mem.write_float(self.BaseAddress - 0x4, xyz.y)
        self.mem.write_float(self.BaseAddress, xyz.z)

class Quest(Memory):
    def __init__(self, mem: Pymem) -> None:
        self.mem = mem
        self.topAddress: int
        self.BaseAddress: int
        self.offsets = []

    def find_base(self) -> int:
        self.topAddress = self.get_add("Pirate.exe", self.convert_pattern_to_bytes(quest_pattern))
        ic(self.topAddress)
        input()
        return self.topAddress

    def read_xyz(self):
        try:
            self.BaseAddress = self.find_base()
            ic(hex(self.BaseAddress))
            self.xyz = XYZ(self.mem.read_float(self.BaseAddress - 8), self.mem.read_float(self.BaseAddress - 4), self.mem.read_float(self.BaseAddress))
        except pymem.exception.MemoryReadError:
            time.sleep(0.5) # if it fails blame slack
            self.read_xyz() #please olaf and starr don't yell at me :c
        return self.xyz

    def write_xyz(self, xyz: XYZ) -> None:
        self.BaseAddress = self.getPtrAddress(self.topAddress, self.offsets)
        self.mem.write_float(self.BaseAddress - 0x8, xyz.x )
        self.mem.write_float(self.BaseAddress - 0x4, xyz.y)
        self.mem.write_float(self.BaseAddress, xyz.z)

from pymem import *
from pymem.process import *
from pymem.pattern import *
import regex as re


    #return final
    #print(bytes.fromhex(hex))
    # TODO figure a way to add back wild cards

mem = Pymem("Pirate.exe")
camera = Cam(mem)
playermodel = PlayerModel(mem)
player = Player(mem)
quest = Quest(mem)

while True:
    ic(quest.read_xyz())
    #ic(camera.write_xyz(XYZ(10.0, 100.0, 100.0)))
    import time
    time.sleep(0.2)
    input
    #break



#cam z #180

#print(bytes.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 43 00 00 00 00 00 00 2A 43'))



#?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 43 00
#b'....\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02C\x00'

#print(bytes.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 43 00'))


#?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 43 00 00 00 00 00 00 2A 43 00 00 00 00 00 00 02 43 00 00 02 43 CD CC CC 3D 00 ?? ?? ?? ?? ?? ?? ?? ?? 0? ?? ?? 00 00 00 01 00 00 E1 43 00 00 96 43 00 00 E1 43 09

#print(hex(gameModule))

#PlayerBaseAddress = mem.read_float(getPointerAddress(mem.base_address + 0x020CF614, offsets=[0x4, 0x8, 0x4C, 0x98, 0x114, 0x0, 0x8, 0x0, 0x5C]))
#print(freePlayerBaseAddress)


# CamBaseAddress = getPointerAddress(self.mem.base_address + 0x020CF614, offsets=[0x4, 0x8, 0x4c, 0x90, 0x4, 0x8, 0x180])
#PlayerBaseAddress = getPointerAddress(mem.base_address + 0x020CF614, offsets=[0x4, 0x8, 0x4C, 0x98, 0x114, 0x0, 0x8, 0x0, 0x5C]) 

# RealBaseAddress = getPointerAddress(self.mem.base_address + 0x02064D60, offsets=[0xC8, 0x10, 0x8, 0x74, 0x24, 0x48])
#QuestBaseAddress = getPointerAddress(self.mem.base_address + 0x00857884, offsets=[0x470, 0x668, 0x53C, 0x8, 0x9F4, 0x978])
# def main():
#     while True:
#         mem = Pymem("Pirate.exe")
#         print(Player(mem).read_xyz())
#main()
#print(hex(PlayerBaseAddress))
# print(self.mem.read_float(RealBaseAddress))
