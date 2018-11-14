from unicorn import *

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
    for hook in _hooks:
        print(hex(hook.type))
        if hook.is_uc_hook():
            emu.uc.hook_add(hook.type, hook.callback)
        elif hook.type == HOOK_OFFSET:
                hook.address += emu.base

# Actual hooks

def hook_code(uc, address, size, user_data):
    print(hex(address))
    for hook in _hooks:
        if address == hook.address:
            hook.callback(uc)
Hook(UC_HOOK_CODE, hook_code)

def hook_intr(mu, intno, user_data):
    print("syscall " + hex(intno))
Hook(UC_HOOK_INTR, hook_intr)