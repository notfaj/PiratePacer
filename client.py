import asyncio
from pymem import Pymem
from functools import cached_property
from loguru import logger
from typing import List
from wizwalker.utils import get_window_title, get_window_rectangle, get_pid_from_handle, set_window_title, get_foreground_window, set_foreground_window, timed_send_key, send_hotkey
from wizwalker import XYZ, Keycode

from hooks.camera import Cam
from hooks.quest import Quest
from hooks.player import Player
from hooks.player_model import PlayerModel



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
            logger.debug("Hooked")


    async def deactivate_all_hooks(self, log: bool = True):
        if not self.hooked:
            return

        self.player_model.close()
        self.player.close()
        self.camera.close()
        self.quest.close()
        self.hooked = False

        if log:
            logger.debug("Unhooked")


    async def teleport(self, xyz: XYZ, move_after: bool = True, log: bool = True):
        self.player.write_xyz(xyz)
        self.camera.write_xyz(xyz)
        self.player_model.write_xyz(xyz)

        if log:
            logger.debug(f"Teleported to {xyz}")

        if move_after:
            await asyncio.sleep(0.1)
            await self.send_key(Keycode.D, 0.1)


    async def quest_teleport(self, move_after: bool = True, log: bool = True):
        quest_xyz = self.quest.read_xyz()
        await asyncio.sleep(0)
        await self.teleport(quest_xyz, move_after, log)