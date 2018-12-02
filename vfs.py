from logging import *
import os

VFS_DIR = "vfs"

def write_vfs_libpad(bin):
    local_dir = os.path.dirname(__file__)
    libpad_path = os.path.join(local_dir, VFS_DIR, "libpad.so")
    log(libpad_path)
    with open(libpad_path, "wb") as f:
        f.write(bin)

_fd_to_os = [0, 1, 2] # standard streams

# ssize_t read(int fd, void *buf, size_t count);
def read_handler(emu, fd, buf_addr, count):
    f = _fd_to_os[fd]
    buf = os.read(f, count)
    result = len(buf)
    emu.uc.mem_write(buf_addr, buf)
    return result

# int open(const char *pathname, int flags, mode_t mode);
def open_handler(emu, pathname_addr, flags, mode):
    pathname = emu.read_string(pathname_addr)
    local_dir = os.path.dirname(__file__)
    local_path = os.path.join(local_dir, VFS_DIR + pathname)
    log("Opening {}".format(pathname))

    if os.path.isfile(local_path):
        next_fd = len(_fd_to_os)
        _fd_to_os.append(os.open(local_path, os.O_RDWR | os.O_BINARY))
        return next_fd
    else:
        return -1

# int close(int fd);
def close_handler(emu, fd):
    f = _fd_to_os[fd]
    os.close(f)
    return 0

# off_t lseek(int fd, off_t offset, int whence);
def lseek_handler(emu, fd, offset, whence):
    f = _fd_to_os[fd]
    result = os.lseek(f, offset, whence)
    return result

# int stat(const char *pathname, struct stat *statbuf);
def stat_handler(emu, pathname_addr, statbuf_addr):
    pathname = emu.read_string(pathname_addr)
    local_dir = os.path.dirname(__file__)
    local_path = os.path.join(local_dir, VFS_DIR + pathname)
    log("Statting {}".format(pathname))

    try:
        # TODO: very naive implementation
        # basically only checks file/path existence
        stat_result = os.stat(local_path)
        result = 0
    except Exception as e:
        log("Not found")
        result = -1

    return result