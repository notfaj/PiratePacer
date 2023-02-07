from wizwalker.utils import XYZ
from icecream import ic
import time
from pymem import *
from pymem.process import *
from pymem.pattern import *
import regex

class Memory():
    def __init__(self) -> None:
        self.mem: Pymem

    def get_add(self, modname, pattern) -> list:
        addresses = pymem.pattern.pattern_scan_all(self.mem.process_handle, pattern)
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

class Cam(Memory):
    def __init__(self, mem: Pymem) -> None:
        self.mem = mem
        self.pattern = rb'\x89\x87\x80\x01\x00\x00\x8B\x76\x7C'
        self.aob_address = None
        self.newmem = None
        self.BaseAddress = None
        self.HookAddress = self.find_base()

    def find_base(self) -> int:
        def Hook_Cam(mem: Pymem, aob: bytes) -> int:
            module = module_from_name(mem.process_handle, "Pirate.exe")
            aob_address = pymem.pattern.pattern_scan_all(module.process_handle, aob)
            
            newmem = pymem.memory.allocate_memory(mem.process_handle, 1000)

            your_variable = pymem.memory.allocate_memory(mem.process_handle, 4)

            #INJECT - E9 ????????         - jmp 06690000
            jump_inst = b"\xE9" + (newmem - (aob_address + 5)).to_bytes(4, byteorder='little', signed=True)
            mem.write_bytes(aob_address, jump_inst, len(jump_inst)) # writes to memory
            
            #66 90    - nop 
            nop = b'\x90'
            mem.write_bytes(aob_address + len(jump_inst), nop, len(nop)) # writes to memory
            
            byte = bytes()
            
            # 50                  - push eax
            # 8D 46               - lea eax,[esi+48]
            byte+= b'\x50\x8D\x46\x48'
            
            # A3 ?? ?? ?? ??        - mov [your_variable],eax
            byte+= b'\xa3' + your_variable.to_bytes(4, byteorder='little', signed=True)
            
            # 58                    - pop eax
            byte+=b'X'
            
            #original code
            #89 87 80 01 00 00        - mov [edi+00000180],eax

            byte+= b'\x89\x87\x80\x01\x00\x00'

            mem.write_bytes(newmem, byte, len(byte)) # writes hook

            #return_jump_offset = (aob_address + len(nop)) - (newmem + len(byte))
            return_jump_offset = (aob_address) - (newmem + len(byte))
            return_jump= b"\xE9" + return_jump_offset.to_bytes(4, byteorder='little', signed=True)
            mem.write_bytes(newmem + len(byte), return_jump, len(return_jump))

            return your_variable, aob_address, newmem

        self.HookAddress, self.aob_address, self.newmem = Hook_Cam(self.mem, self.pattern)
        
        
        return self.HookAddress
    
    def close(self):
        self.pattern = b'\x89\x87\x80\x01\x00\x00\x8B\x76\x7C'
        self.mem.write_bytes(self.aob_address, self.pattern, len(self.pattern)) 
        pymem.memory.free_memory(self.mem.process_handle, self.newmem)
        pymem.memory.free_memory(self.mem.process_handle, self.HookAddress)

    def read_xyz(self) -> XYZ:
        #ic(hex(self.BaseAddress), self.BaseAddress)
        try:
            self.BaseAddress = self.mem.read_int(self.HookAddress)
            ic(self.BaseAddress, hex(self.BaseAddress))
            self.xyz = XYZ(self.mem.read_float((self.BaseAddress - 0x8)), self.mem.read_float((self.BaseAddress - 0x4)), self.mem.read_float(self.BaseAddress))
        except:
            time.sleep(0.1)
            self.read_xyz()
            
        return self.xyz
    
    def write_xyz(self, xyz: XYZ) -> None:
        try:
            self.BaseAddress = self.mem.read_int(self.HookAddress)
            self.mem.write_float(self.BaseAddress - 0x8, xyz.x )
            self.mem.write_float(self.BaseAddress - 0x4, xyz.y)
            self.mem.write_float(self.BaseAddress, xyz.z)
        except:
            time.sleep(0.1)
            self.write_xyz

class PlayerModel(Memory):
    def __init__(self, mem: Pymem) -> None:
        self.mem = mem
        self.BaseAddress = None

    def find_base(self):
        base = self.mem.read_int(self.mem.base_address + 0x020CF614)
        self.base_address = self.getPtrAddress(base, [0x4, 0x8, 0x4C, 0x98, 0x114, 0x00, 0x08, 0x00, 0x5C])
        return self.base_address
    
    def read_xyz(self) -> XYZ:
        self.BaseAddress = self.find_base()
        self.xyz = XYZ(self.mem.read_float(self.BaseAddress - 0x8), self.mem.read_float(self.BaseAddress - 0x4), self.mem.read_float(self.BaseAddress))
        return self.xyz
    
    def write_xyz(self, xyz: XYZ) -> None:
        self.BaseAddress = self.find_base()
        self.mem.write_float(self.BaseAddress - 0x8, xyz.x )
        self.mem.write_float(self.BaseAddress - 0x4, xyz.y)
        self.mem.write_float(self.BaseAddress, xyz.z)

    def close(self):
        pass

class Player(Memory):
    def __init__(self, mem: Pymem) -> None:
        self.mem = mem
        self.pattern = rb'\x89\x46\x48\xC6\x47\x68\x01\x8D\x4C\x24\x6C\xC7\x84\x24\x80\x01\x00\x00\xFF\xFF\xFF\xFF'
        self.HookAddress = None
        self.aob_address = None
        self.newmem = None
        self.BaseAddress = self.find_base()
        
    def find_base(self) -> int:
        def Hook_Real(mem: Pymem, aob: bytes) -> int:
            module = module_from_name(mem.process_handle, "Pirate.exe")
            aob_address = pymem.pattern.pattern_scan_all(module.process_handle, aob)
            
            newmem = pymem.memory.allocate_memory(mem.process_handle, 1000)

            your_variable = pymem.memory.allocate_memory(mem.process_handle, 4)

            #INJECT - E9 87129F05         - jmp 06690000
            jump_inst = b"\xE9" + (newmem - (aob_address + 5)).to_bytes(4, byteorder='little', signed=True)
            #jump_inst = b"\xE9" + newmem.to_bytes(4, byteorder='little', signed=True)
            mem.write_bytes(aob_address, jump_inst, len(jump_inst)) # writes to memory
            
            #Pirate.exe+89ED79 - 66 90    - nop 2
            nop = b'f\x90'
            mem.write_bytes(aob_address + len(jump_inst), nop, len(nop)) # writes to memory
            
            byte = bytes()
            
            # 50                    - push eax
            # 8D 46 48              - lea eax,[esi+48]
            byte+= b'P\x8dFH'
            
            # A3 00 10 D3 04        - mov [your_variable],eax
            byte+= b'\xa3' + your_variable.to_bytes(4, byteorder='little', signed=True)
            
            # 58                    - pop eax
            byte+=b'X'
            
            # 89 46 48              - mov [esi+48],eax
            # C6 47 68 01           - mov byte ptr [edi+68],01
            byte+=b'x89FH\xc6Gh\x01'
            mem.write_bytes(newmem, byte, len(byte))

            # E9 65 ED F6 FB        - jmp Pirate.exe+89ED7B
            #return_jump_offset = (aob_address + len(jump_inst) - (newmem + len(byte)))
            return_jump_offset = (aob_address + len(nop)) - (newmem + len(byte))
            return_jump= b"\xE9" + return_jump_offset.to_bytes(4, byteorder='little', signed=True)
            mem.write_bytes(newmem + len(byte), return_jump, len(return_jump))
    
            return your_variable, aob_address, newmem

        self.HookAddress, self.aob_address, self.newmem = Hook_Real(self.mem, self.pattern)
        return self.HookAddress
    
    def close(self):
        self.pattern = b'\x89\x46\x48\xC6\x47\x68\x01\x8D\x4C\x24\x6C\xC7\x84\x24\x80\x01\x00\x00\xFF\xFF\xFF\xFF'
        self.mem.write_bytes(self.aob_address, self.pattern, len(self.pattern)) 
        pymem.memory.free_memory(self.mem.process_handle, self.newmem)
        pymem.memory.free_memory(self.mem.process_handle, self.HookAddress)

    def read_xyz(self) -> XYZ:
        #ic(hex(self.BaseAddress), self.BaseAddress)
        try:
            self.BaseAddress = self.mem.read_int(self.HookAddress)
            ic(self.BaseAddress, hex(self.BaseAddress))
            self.xyz = XYZ(self.mem.read_float((self.BaseAddress - 0x8)), self.mem.read_float((self.BaseAddress - 0x4)), self.mem.read_float(self.BaseAddress))
        except:
            time.sleep(0.1)
            self.read_xyz()
            
        return self.xyz
    
    def write_xyz(self, xyz: XYZ) -> None:
        try:
            self.BaseAddress = self.mem.read_int(self.HookAddress)
            self.mem.write_float(self.BaseAddress - 0x8, xyz.x )
            self.mem.write_float(self.BaseAddress - 0x4, xyz.y)
            self.mem.write_float(self.BaseAddress, xyz.z)
        except:
            time.sleep(0.1)
            self.write_xyz

class Quest(Memory):
    def __init__(self, mem: Pymem) -> None:
        self.mem = mem
        self.pattern = rb'\x89\x48\x08\x8A\x44\x24\x1E' # 89 48 08 8A 44 24 1E
        self.aob_address = None
        self.newmem = None
        self.BaseAddress = None
        self.HookAddress = self.find_base()

    def find_base(self) -> int:
        def Hook_Quest(mem:Pymem, aob:bytes):
            module = module_from_name(mem.process_handle, "Pirate.exe")
            aob_address = pymem.pattern.pattern_scan_all(module.process_handle, aob)

            newmem = pymem.memory.allocate_memory(mem.process_handle, 1000)

            your_variable = pymem.memory.allocate_memory(mem.process_handle, 4)
            #INJECT - E9 ????????         - jmp 06690000
            jump_inst = b"\xE9" + (newmem - (aob_address + 5)).to_bytes(4, byteorder='little', signed=True)
            mem.write_bytes(aob_address, jump_inst, len(jump_inst)) # writes to memory

            nop = b'f\x90'
            mem.write_bytes(aob_address + len(jump_inst), nop, len(nop)) # writes to memory

            byte = bytes()
            # 067C0000 - 56                    - push esi
            byte += b'\x56'
            # 067C0001 - 8D 70 08              - lea esi,[eax+08]
            byte += b'\x8D\x70\x08'
            # 067C0004 - 89 35 00107C06        - mov [your_variable],esi
            byte += b'\x89\x35' + your_variable.to_bytes(4, byteorder='little', signed=True)
            # 067C000A - 5E                    - pop esi
            byte += b'\x5E'
            # 067C000B - 89 48 08              - mov [eax+08],ecx
            byte += b'\x89\x48\x08'
            # 067C000E - 8A 44 24 1E           - mov al,[esp+1E]
            byte += b'\x8A\x44\x24\x1E'
            mem.write_bytes(newmem, byte, len(byte)) # writes hook
            
            return_jump_offset = (aob_address) - (newmem + len(byte))
            return_jump= b"\xE9" + return_jump_offset.to_bytes(4, byteorder='little', signed=True)
            mem.write_bytes(newmem + len(byte), return_jump, len(return_jump))
            return your_variable, aob_address, newmem
        
        self.HookAddress, self.aob_address, self.newmem = Hook_Quest(self.mem, self.pattern)
        return self.HookAddress
    
    def close(self):
        #TODO:
        # Find out how to use raw bytes
        self.pattern = b'\x89\x48\x08\x8A\x44\x24\x1E'
        self.mem.write_bytes(self.aob_address, self.pattern, len(self.pattern)) 
        pymem.memory.free_memory(self.mem.process_handle, self.newmem)
        pymem.memory.free_memory(self.mem.process_handle, self.HookAddress)

    def read_xyz(self) -> XYZ:
        #ic(hex(self.BaseAddress), self.BaseAddress)
        try:
            self.BaseAddress = self.mem.read_int(self.HookAddress)
            self.xyz = XYZ(self.mem.read_float((self.BaseAddress - 0x8)), self.mem.read_float((self.BaseAddress - 0x4)), self.mem.read_float(self.BaseAddress))
        except:
            time.sleep(0.1)
            self.read_xyz()
            
        return self.xyz
    
    def write_xyz(self, xyz: XYZ) -> None:
        try:
            self.BaseAddress = self.mem.read_int(self.HookAddress)
            self.mem.write_float(self.BaseAddress - 0x8, xyz.x )
            self.mem.write_float(self.BaseAddress - 0x4, xyz.y)
            self.mem.write_float(self.BaseAddress, xyz.z)
        except:
            time.sleep(0.1)
            self.write_xyz

import asyncio
from hotkey import Hotkey, Keycode, ModifierKeys, Listener
import subprocess
def isPirateRunning():
    progs = str(subprocess.check_output('tasklist'))
    if "Pirate.exe" in progs:
        
        return True
    else:
        return False

async def main():
    async def questtp():
        questcord = quest.read_xyz()
        player.write_xyz(questcord)
        cam.write_xyz(questcord)
        playermodel.write_xyz(questcord)
        ic('teleported')

    async def unhook():
        quest.close()
        player.close()
        cam.close()
        playermodel.close()
        ic('unhooked')
    try:
        mem = Pymem("Pirate.exe")
    except pymem.exception.ProcessNotFound:
        print("Pirate101 Isn't running waiting for Pirate to start...")
        while True:
            if isPirateRunning() == True:
                ic("Found Pirate Instance!")
                break
            await asyncio.sleep(1.5)
        mem = Pymem("Pirate.exe")
        
    playermodel = PlayerModel(mem)
    player = Player(mem)
    cam = Cam(mem)
    quest = Quest(mem)

    hotkeys = [Hotkey(Keycode.A, questtp, ModifierKeys.CTRL), Hotkey(Keycode.Q, unhook, ModifierKeys.CTRL)] 
    listener = Listener(hotkeys)
    listener.listen_forever()
    # your program heresda
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())





# questcord = quest.read_xyz()

# player.write_xyz(questcord)
# cam.write_xyz(questcord)
# playermodel.write_xyz(questcord)


