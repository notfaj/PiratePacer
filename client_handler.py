import asyncio
from wizwalker.utils import get_windows_from_predicate, order_clients
from typing import List, Callable, Coroutine
from loguru import logger

import ctypes
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

from client import Client



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
                logger.debug("Waiting for Pirate101 to be opened...")
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