from logging import *
import sys
import os

SYSCALL_INT_NUMBER = 0x2

_syscall_handlers = []

class SyscallHandler():
    def __init__(self, name, number, argument_count, callback):
        self.name = name
        self.number = number
        self.argument_count = argument_count
        self.callback = callback

        _syscall_handlers.append(self)

def handle(uc, syscall_number, args):
    log("Syscall {:#x}".format(syscall_number))
    for handler in _syscall_handlers:
        if handler.number == syscall_number:
            log("{}({})".format(handler.name, ", ".join(["{:#010x}".format(arg) for arg in args[:handler.argument_count]])))
            return handler.callback(uc, *args[:handler.argument_count])
    else:
        sys.exit()

# int open(const char *pathname, int flags, mode_t mode);
def open_handler(uc, filename_addr, flags, mode):
    log("in open")
    return -1
SyscallHandler("open", 5, 3, open_handler)