from logging import *

FS_DIR = "./vfs"

def open_handler(emu, filename_addr, flags, mode):
    log(emu.read_string(filename_addr))
    return -1