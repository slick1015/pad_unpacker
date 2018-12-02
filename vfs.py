from logging import *
import os

FS_DIR = "./vfs"

def write_vfs_libpad(bin):
    local_dir = os.path.dirname(__file__)
    libpad_path = os.path.join(local_dir, FS_DIR, "libpad.so")
    with open(libpad_path, "wb") as f:
        f.write(bin)

_fd_to_os = [0, 1, 2] # standard streams

def open_handler(emu, filename_addr, flags, mode):
    log(emu.read_string(filename_addr))
    return -1