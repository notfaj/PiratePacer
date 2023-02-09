from pymem import Pymem
from pymem.process import module_from_name
from pymem.memory import allocate_memory, free_memory
from pymem.pattern import pattern_scan_all

from wizwalker import XYZ
import time

from .memory import Memory



class Quest(Memory):
    def __init__(self, mem: Pymem) -> None:
        super().__init__(mem)
        self.pattern = rb'\x89\x48\x08\x8A\x44\x24\x1E' # 89 48 08 8A 44 24 1E
        self.aob_address = None
        self.newmem = None
        self.BaseAddress = None
        self.HookAddress = self.find_base()

    def find_base(self) -> int:
        def Hook_Quest(mem:Pymem, aob:bytes):
            module = module_from_name(mem.process_handle, "Pirate.exe")
            aob_address = pattern_scan_all(module.process_handle, aob)

            newmem = allocate_memory(mem.process_handle, 1000)

            your_variable = allocate_memory(mem.process_handle, 4)
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
        self.active = True
        return self.HookAddress
    
    def close(self):
        #TODO:
        # Find out how to use raw bytes
        self.pattern = b'\x89\x48\x08\x8A\x44\x24\x1E'
        self.mem.write_bytes(self.aob_address, self.pattern, len(self.pattern)) 
        free_memory(self.mem.process_handle, self.newmem)
        free_memory(self.mem.process_handle, self.HookAddress)
        self.active = False

    def read_xyz(self) -> XYZ:
        #logger.debug(hex(self.BaseAddress), self.BaseAddress)
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