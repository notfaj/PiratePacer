# from loguru import logger
import loguru
from loguru import logger

from wizwalker.utils import XYZ, Rectangle, get_pid_from_handle, order_clients, get_windows_from_predicate, set_window_title, set_foreground_window, get_foreground_window, timed_send_key, send_hotkey
from wizwalker.client import get_window_rectangle, get_window_title
import time
import datetime
from pymem import *
from pymem.process import *
from pymem.pattern import *
import regex
from typing import List, Callable, Coroutine

import asyncio
from hotkey import Hotkey, Keycode, ModifierKeys, Listener

import ctypes
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

from functools import cached_property



tool_version = '0.0.0'
tool_name = 'Deimos'
repo_name = tool_name + '-Pirate101'
branch = 'master'


def generate_timestamp() -> str:
	# generates a timestamp and makes the symbols filename-friendly
	time = str(datetime.datetime.now())
	time_list = time.split('.')
	time_stamp = str(time_list[0])
	time_stamp = time_stamp.replace('/', '-').replace(':', '-')
	return time_stamp




class Memory():
    def __init__(self, mem: Pymem) -> None:
        self.mem = mem
        self.active = False

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
        super().__init__(mem)
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

        self.active = True
        return self.HookAddress
    
    def close(self):
        self.pattern = b'\x89\x87\x80\x01\x00\x00\x8B\x76\x7C'
        self.mem.write_bytes(self.aob_address, self.pattern, len(self.pattern)) 
        pymem.memory.free_memory(self.mem.process_handle, self.newmem)
        pymem.memory.free_memory(self.mem.process_handle, self.HookAddress)
        self.active = False

    def read_xyz(self) -> XYZ:
        #logger.debug(hex(self.BaseAddress), self.BaseAddress)
        try:
            self.BaseAddress = self.mem.read_int(self.HookAddress)
            loguru.logger.debug(self.BaseAddress, hex(self.BaseAddress))
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
        super().__init__(mem)
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
        super().__init__(mem)
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
        self.active = True
        return self.HookAddress
    
    def close(self):
        self.pattern = b'\x89\x46\x48\xC6\x47\x68\x01\x8D\x4C\x24\x6C\xC7\x84\x24\x80\x01\x00\x00\xFF\xFF\xFF\xFF'
        self.mem.write_bytes(self.aob_address, self.pattern, len(self.pattern)) 
        pymem.memory.free_memory(self.mem.process_handle, self.newmem)
        pymem.memory.free_memory(self.mem.process_handle, self.HookAddress)
        self.active = False

    def read_xyz(self) -> XYZ:
        #logger.debug(hex(self.BaseAddress), self.BaseAddress)
        try:
            self.BaseAddress = self.mem.read_int(self.HookAddress)
            loguru.logger.debug(self.BaseAddress, hex(self.BaseAddress))
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
        super().__init__(mem)
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
        self.active = True
        return self.HookAddress
    
    def close(self):
        #TODO:
        # Find out how to use raw bytes
        self.pattern = b'\x89\x48\x08\x8A\x44\x24\x1E'
        self.mem.write_bytes(self.aob_address, self.pattern, len(self.pattern)) 
        pymem.memory.free_memory(self.mem.process_handle, self.newmem)
        pymem.memory.free_memory(self.mem.process_handle, self.HookAddress)
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



class Client(): #Thanks to Starrfox and wizwalker for most of the methods here. We're intentionally mimicking how WW handles clients just to give some parity.
    def __init__(self, handle: int):
        self.window_handle = handle
        self.original_title = get_window_title(self.window_handle)

        self.process_id: str = get_pid_from_handle(self.window_handle)
        self.process_mem: Pymem = Pymem(self.process_id)
        # self.window_rectangle: Rectangle = get_window_rectangle(self.window_handle)

        self.player: Player = None
        self.player_model: PlayerModel = None
        self.camera: Cam = None
        self.quest: Quest = None
        self.hooked: bool = False


    def __repr__(self):
        return f"<Client {self.window_handle=} {self.process_id=}>"


    @property
    def title(self) -> str:
        """
        Get or set this window's title
        """
        return get_window_title(self.window_handle)


    @title.setter
    def title(self, window_title: str):
        set_window_title(self.window_handle, window_title)


    @property
    def is_foreground(self) -> bool:
        """
        If this client is the foreground window

        Set this to True to bring it to the foreground
        """
        return get_foreground_window() == self.window_handle


    @is_foreground.setter
    def is_foreground(self, value: bool):
        if value is False:
            return

        set_foreground_window(self.window_handle)


    @property
    def window_rectangle(self):
        """
        Get this client's window rectangle
        """
        return get_window_rectangle(self.window_handle)

    @cached_property
    def process_id(self) -> int:
        """
        Client's process id
        """
        return get_pid_from_handle(self.window_handle)


    async def send_key(self, key: Keycode, seconds: float = 0):
        """
        Send a key

        Args:
            key: The Keycode to send
            seconds: How long to send it for
        """
        await timed_send_key(self.window_handle, key, seconds)


    async def send_hotkey(self, modifers: List[Keycode], key: Keycode):
        """
        send a hotkey

        Args:
            modifers: The key modifers i.e CTRL, ALT
            key: The key being modified
        """
        await send_hotkey(self.window_handle, modifers, key)


    async def activate_all_hooks(self, log: bool = True):
        if self.hooked:
            return

        self.player_model = PlayerModel(self.process_mem)
        self.player = Player(self.process_mem)
        self.camera = Cam(self.process_mem)
        self.quest = Quest(self.process_mem)
        self.hooked = True

        if log:
            loguru.logger.debug("Hooked")


    async def deactivate_all_hooks(self, log: bool = True):
        if not self.hooked:
            return

        self.player_model.close()
        self.player.close()
        self.camera.close()
        self.quest.close()
        self.hooked = False

        if log:
            loguru.logger.debug("Unhooked")


    async def teleport(self, xyz: XYZ, move_after: bool = True, log: bool = True):
        self.player.write_xyz(xyz)
        self.camera.write_xyz(xyz)
        self.player_model.write_xyz(xyz)

        if log:
            loguru.logger.debug(f"Teleported to {xyz}")

        if move_after:
            await asyncio.sleep(0.1)
            await self.send_key(Keycode.D, 0.1)


    async def quest_teleport(self, move_after: bool = True, log: bool = True):
        quest_xyz = self.quest.read_xyz()
        await asyncio.sleep(0)
        await self.teleport(quest_xyz, move_after, log)






def get_all_handles_with_name(name: str) -> list:
    """
    Get handles to all currently open game clients
    """

    def callback(handle):
        class_name = ctypes.create_unicode_buffer(len(name))
        user32.GetClassNameW(handle, class_name, len(name) + 1)
        if name == class_name.value:
            return True

    return get_windows_from_predicate(callback)





class ClientHandler():
    def __init__(self):
        self.managed_handles: List[int] = []
        self.clients: List[Client] = []
        self.client_class: str = "Client"


    def get_handles(self, new_only: bool = True):
        handles = get_all_handles_with_name(self.client_class)
        if not new_only:
            return handles

        return [h for h in handles if h not in self.managed_handles]


    async def wait_for_handle(self, interval: float = 1.0, log: bool = True):
        while len(get_all_handles_with_name(self.client_class)) == 0:
            if log:
                loguru.logger.debug("Waiting for Pirate101 to be opened...")
            await asyncio.sleep(interval)


    def get_clients(self, new_only: bool = True):
        self.managed_handles = self.get_handles(new_only)
        for handle in self.managed_handles:
            self.clients.append(Client(handle))


    def order_clients(self):
        self.clients = order_clients(self.clients)


    def get_ordered_clients(self, new_only: bool = True):
        self.get_clients(new_only)
        self.order_clients()


    async def activate_all_client_hooks(self, log: bool = True):
        await asyncio.gather(*[client.activate_all_hooks(log) for client in self.clients])
        for i, client in enumerate(self.clients):
            client.title = f"[p{i + 1}] " + client.original_title


    async def deactivate_all_client_hooks(self, log: bool = True):
        await asyncio.gather(*[client.deactivate_all_hooks(log) for client in self.clients])
        for client in self.clients:
            client.title = client.original_title



    def get_foreground_client(self):
        foreground_clients = [c for c in self.clients if c.is_foreground]
        if foreground_clients:
            return foreground_clients[0]

        else:
            return None


    async def foreground_coro(self, coro: Coroutine, *args, **kwargs):
        """(Async) Runs a method of the foreground client, but only on the foreground client. Does nothing if no clients are selected."""
        foreground_client = self.get_foreground_client()
        if foreground_client:
            await coro(foreground_client, *args, **kwargs)


    def foreground_method(self, method: Callable, *args, **kwargs):
        """Runs a method of the foreground client, but only on the foreground client. Does nothing if no clients are selected."""
        foreground_client = self.get_foreground_client()
        if foreground_client:
            method(foreground_client, *args, **kwargs)




# import asyncio
# from hotkey import Hotkey, Keycode, ModifierKeys, Listener
# import subprocess
# def isPirateRunning():
#     progs = str(subprocess.check_output('tasklist'))
#     if "Pirate.exe" in progs:
        
#         return True
#     else:
#         return False

async def main():
    pacer = ClientHandler()
    await pacer.wait_for_handle()
    pacer.get_ordered_clients()
    await pacer.activate_all_client_hooks()

    # async def unhook():
    #     quest.close()
    #     player.close()
    #     cam.close()
    #     playermodel.close()
    #     ic('unhooked')
    # try:
    #     mem = Pymem("Pirate.exe")
    # except pymem.exception.ProcessNotFound:
    #     print("Pirate101 Isn't running waiting for Pirate to start...")
    #     while True:
    #         if isPirateRunning() == True:
    #             ic("Found Pirate Instance!")
    #             break
    #         await asyncio.sleep(1.5)
    #     mem = Pymem("Pirate.exe")
        
    # playermodel = PlayerModel(mem)
    # player = Player(mem)
    # cam = Cam(mem)
    # quest = Quest(mem)

    async def quest_teleport_hotkey():
        await pacer.foreground_coro(Client.quest_teleport)

    async def close_hotkey():
        await pacer.deactivate_all_client_hooks()
        raise KeyboardInterrupt


    hotkeys = [Hotkey(Keycode.F7, quest_teleport_hotkey), Hotkey(Keycode.F9, close_hotkey)] 
    listener = Listener(hotkeys)
    listener.listen_forever()
    # your program heresda
    while True:
        await asyncio.sleep(1)



if __name__ == "__main__":
    current_log = loguru.logger.add(f"logs/{tool_name} - {generate_timestamp()}.log", encoding='utf-8', enqueue=True, backtrace=True)
    asyncio.run(main())
    loguru.logger.remove()





# questcord = quest.read_xyz()

# player.write_xyz(questcord)
# cam.write_xyz(questcord)
# playermodel.write_xyz(questcord)


