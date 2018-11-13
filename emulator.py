from unicorn import *
from unicorn.arm_const import *
import logging
import hooks

STACK_SIZE = 64 * 1024 * 1024  # I don't think we'll ever need more than 64 MB for the stack
BIN_SIZE   = 128 * 1024 * 1024 # allocate 128 MB for the binary, probably overkill

class Emulator():
    def __init__(self, binary, base=0x400000):
        self.base = base
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.next_alloc_base = self.base

        bin_base = self.alloc(BIN_SIZE) # allocate 128 MB for the binary, probably overkill
        self.uc.mem_write(bin_base, binary)

        stack_base = self.alloc(STACK_SIZE)
        self.uc.reg_write(UC_ARM_REG_SP, stack_base  + (STACK_SIZE // 2)) # point SP to the middle of the stack, just to be safe

        hooks.register(self)

    def start(self, start_address, end_address):
        self.uc.reg_write(UC_ARM_REG_PC, start_address)
        self.uc.emu_start(start_address, end_address)

    def stop(self):
        self.uc.emu_stop()

    def alloc(self, size):
        alloc_base = self.next_alloc_base
        self.uc.mem_map(self.next_alloc_base, size)
        self.next_alloc_base += size
        return alloc_base

    def allocations(self):
        return [reg for reg in self.uc.mem_regions()]

    def read_string(self, address):
        buf = []
        while True:
            c = self.uc.mem_read(address, 1)[0]
            if c == 0: # strings end with a null terminator
                break
            buf.append(c)
            address += 1
        return "".join(map(chr, buf))