from unicorn import *
from unicorn.arm_const import *
from logging import log
import syscalls

# Hooking definitions

HOOK_ADDRESS = 0xF000 | 1 # hook at absolute address
HOOK_OFFSET  = 0xF000 | 2 # hook at offset from the loaded binary's base

_hooks = []

class Hook():
    def __init__(self, hook_type, callback, address=None):
        self.type = hook_type
        self.callback = callback
        self.address = address

        _hooks.append(self)
    
    def is_uc_hook(self):
        if self.type in [HOOK_ADDRESS, HOOK_OFFSET]:
            return False
        return True

def register(emu):
    global _emu
    _emu = emu
    for hook in _hooks:
        if hook.is_uc_hook():
            emu.uc.hook_add(hook.type, hook.callback)
        elif hook.type == HOOK_OFFSET:
                hook.address += emu.base

# Actual hooks

def hook_code(uc, address, size, user_data):
    # log("> Instruction at {:#010x}".format(address))

    for hook in _hooks:
        if address == hook.address:
            hook.callback(uc)
Hook(UC_HOOK_CODE, hook_code)

def hook_intr(uc, intno, user_data):
    # log("# Interrupt number {:#x}".format(intno))

    if intno == syscalls.SYSCALL_INT_NUMBER:
        # register r7 contains the syscall_number
        syscall_number = uc.reg_read(UC_ARM_REG_R7)
        # registers r0-r6, including r6 contain the arguments
        args = [uc.reg_read(reg_idx) for reg_idx in range(UC_ARM_REG_R0, UC_ARM_REG_R6 + 1)]

        result = syscalls.handle(_emu, syscall_number, args)
        # register r0 will contain the result of the syscall
        if result != None:
            uc.reg_write(UC_ARM_REG_R0, result)
Hook(UC_HOOK_INTR, hook_intr)