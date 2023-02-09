from loguru import logger
import datetime

import asyncio
from hotkey import Hotkey, Keycode, ModifierKeys, Listener

import ctypes
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32


from client import Client
from client_handler import ClientHandler


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
    current_log = logger.add(f"logs/{tool_name} - {generate_timestamp()}.log", encoding='utf-8', enqueue=True, backtrace=True)
    asyncio.run(main())
    logger.remove()