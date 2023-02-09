from pymem import Pymem
from pymem.process import module_from_name
from pymem.memory import allocate_memory, free_memory
from pymem.pattern import pattern_scan_all

from loguru import logger
import time
from wizwalker import XYZ

from .memory import Memory



class Player(Memory):
    def __init__(self, mem: Pymem) -> None:
        super().__init__(mem)
        self.pattern = rb'\x89\x46\x48\xC6\x47\x68\x01\x8D\x4C\x24\x6C\xC7\x84\x24\x80\x01\x00\x00\xFF\xFF\xFF\xFF'
        self.HookAddress = None
        self.aob_address = None
        self.newmem = None
        self.BaseAddress = self.find_base()
        
    def find_base(self) -> int:
        def Hook_Real(mem: Pymem, aob: bytes) -> int:
            module = module_from_name(mem.process_handle, "Pirate.exe")
            aob_address = pattern_scan_all(module.process_handle, aob)
            
            newmem = allocate_memory(mem.process_handle, 1000)

            your_variable = allocate_memory(mem.process_handle, 4)

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
        self.active = True
        return self.HookAddress
    
    def close(self):
        self.pattern = b'\x89\x46\x48\xC6\x47\x68\x01\x8D\x4C\x24\x6C\xC7\x84\x24\x80\x01\x00\x00\xFF\xFF\xFF\xFF'
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