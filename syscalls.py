from logging import *
from unicorn.arm_const import *
import os
import sys
import vfs

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
            formatted_args = ", ".join(["{:#010x}".format(arg) for arg in args[:handler.argument_count]])
            log("{}({})".format(handler.name, formatted_args))

            linc()
            result = handler.callback(emu, *args[:handler.argument_count])
            ldec()

            return result
    else:
        log("Unhandled syscall: {:#x}".format(syscall_number))
        emu.stop()

# void exit(int status);
def exit_handler(emu, status):
    log("Exiting program!!!")
    emu.stop()
SyscallHandler("exit", 0x1, 1, exit_handler)

# void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
def mmap_handler(emu, addr, length, prot, flags, fd, offset):
    result = emu.alloc(length)
    return result
SyscallHandler("mmap", 0xc0, 6, mmap_handler)

# int munmap(void *addr, size_t length);
def mummap_handler(emu, addr, length):
    # let this pass through to keep allocations around for debugging
    # memory is infinite anyways
    pass
SyscallHandler("mummap", 0x5b, 2, mummap_handler)

# int mprotect(void *addr, size_t len, int prot);
def mprotect_handler(emu, addr, len, prot):
    # all memory has rwx permission, not applicable
    pass
SyscallHandler("mprotect", 0x7d, 3, mprotect_handler)

# void __clear_cache(char *begin, char *end)
def clear_cache_handler(emu, begin, end):
    # this doesn't apply since we aren't dealing with an instruction cache
    pass
SyscallHandler("__clear_cache", 0xf0002, 2, clear_cache_handler)

# ssize_t read(int fd, void *buf, size_t count);
SyscallHandler("read", 0x3, 3, vfs.read_handler)
# int open(const char *pathname, int flags, mode_t mode);
SyscallHandler("open", 0x5, 3, vfs.open_handler)
# int close(int fd);
SyscallHandler("close", 0x6, 1, vfs.close_handler)
# off_t lseek(int fd, off_t offset, int whence);
SyscallHandler("lseek", 0x13, 3, vfs.lseek_handler)
# int stat(const char *pathname, struct stat *statbuf);
SyscallHandler("stat64", 0xc3, 2, vfs.stat_handler)
# int lstat(const char *pathname, struct stat *statbuf);
# same handler as stat because it's really only used to check existence
SyscallHandler("lstat64", 0xc4, 2, vfs.stat_handler)