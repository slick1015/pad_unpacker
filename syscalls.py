from logging import *
import os
import sys

SYSCALL_INT_NUMBER = 0x2

_syscall_handlers = []

class SyscallHandler():
    def __init__(self, name, number, argument_count, callback):
        self.name = name
        self.number = number
        self.argument_count = argument_count
        self.callback = callback

        _syscall_handlers.append(self)

def handle(emu, syscall_number, args):
    # log("Syscall {:#x}".format(syscall_number))

    for handler in _syscall_handlers:
        if handler.number == syscall_number:
            log("{}({})".format(handler.name, ", ".join(["{:#010x}".format(arg) for arg in args[:handler.argument_count]])))

            linc()
            result = handler.callback(emu, *args[:handler.argument_count])
            ldec()

            return result
    else:
        log("Unhandled syscall: {:#x}".format(syscall_number))
        emu.stop()

# Actual syscalls

# int open(const char *pathname, int flags, mode_t mode);
def open_handler(emu, filename_addr, flags, mode):
    log(emu.read_string(filename_addr))
    return -1
SyscallHandler("open", 0x5, 3, open_handler)