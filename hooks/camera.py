from pymem import Pymem
from pymem.pattern import pattern_scan_all
from pymem.memory import allocate_memory, free_memory
from pymem.process import module_from_name

from loguru import logger
import time

from wizwalker import XYZ

from .memory import Memory




class Cam(Memory):
    def __init__(self, mem: Pymem) -> None:
        super().__init__(mem)
        self.pattern = rb'\x89\x87\x80\x01\x00\x00\x8B\x76\x7C'
        self.aob_address = None
        self.newmem = None
        self.BaseAddress = None
        self.HookAddress = self.find_base()

    def find_base(self) -> int:
        def Hook_Cam(mem: Pymem, aob: bytes) -> int:
            module = module_from_name(mem.process_handle, "Pirate.exe")
            aob_address = pattern_scan_all(module.process_handle, aob)
            
            newmem = allocate_memory(mem.process_handle, 1000)

            your_variable = allocate_memory(mem.process_handle, 4)

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

        self.active = True
        return self.HookAddress
    
    def close(self):
        self.pattern = b'\x89\x87\x80\x01\x00\x00\x8B\x76\x7C'
        self.mem.write_bytes(self.aob_address, self.pattern, len(self.pattern)) 
        free_memory(self.mem.process_handle, self.newmem)
        free_memory(self.mem.process_handle, self.HookAddress)
        self.active = False

    def read_xyz(self) -> XYZ:
        #logger.debug(hex(self.BaseAddress), self.BaseAddress)
        try:
            self.BaseAddress = self.mem.read_int(self.HookAddress)
            logger.debug(self.BaseAddress, hex(self.BaseAddress))
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