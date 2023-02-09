from pymem import Pymem
from wizwalker import XYZ

from .memory import Memory



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