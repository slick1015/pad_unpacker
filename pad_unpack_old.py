import sys
import os
import struct
import binascii
import time
from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn.arm_const import *

bin_dir = "./binaries"
fs_dir = "./fs"
dump_dir = "./dump"
emulation_base = 0x1000


def dump_bytes(b, filename):
    with open(os.path.join(dump_dir, filename), "wb") as f:
        f.write(b)

file_handles = [] # index is file descriptor, value is file handle

# int open(const char *pathname, int flags, mode_t mode);
def open_handler(mu, filename_addr, flags, mode):
    result = -1
    filename = read_string(mu, filename_addr)
    log("open({}, {}, {})".format(filename, hex(flags), hex(mode)))
    inc_indent()

    try:
        handle = os.open(fs_dir + filename, os.O_RDWR | os.O_BINARY)
        result = len(file_handles) # make the fd the next index in the array
        file_handles.append(handle)
        log("Added {} as fd {}".format(filename, result))
    except Exception as e:
        log(e)

    dec_indent()
    return result

# off_t lseek(int fd, off_t offset, int whence);
def lseek_handler(mu, fd, offset, whence):
    result = -1
    log("lseek({}, {}, {})".format(fd, hex(offset), hex(whence)))
    inc_indent()
    
    try:
        handle = file_handles[fd]
        result = os.lseek(handle, offset, whence)
    except Exception as e:
        log(e)

    dec_indent()
    return result

# ssize_t read(int fd, void *buf, size_t count);
def read_handler(mu, fd, buf_addr, count):
    result = -1
    log("read({}, {}, {})".format(fd, hex(buf_addr), hex(count)))
    inc_indent()
    
    try:
        handle = file_handles[fd]
        buf = os.read(handle, count)
        result = len(buf)
        mu.mem_write(buf_addr, buf)
    except Exception as e:
        log(e)

    dec_indent()
    return result

# int close(int fd);
def close_handler(mu, fd):
    result = -1
    log("close({})".format(fd))
    inc_indent()
    
    try:
        handle = file_handles[fd]
        os.close(handle)
        result = 0
    except Exception as e:
        log(e)

    dec_indent()
    return result

# int munmap(void *addr, size_t length);
def munmap_handler(mu, addr, length):
    result = -1
    log("munmap({}, {})".format(hex(addr), hex(length)))
    inc_indent()
    
    try:
        log("Ignoring deallocation of {} bytes at {}".format(hex(length), hex(addr)))
        result = 0
    except Exception as e:
        log(e)

    dec_indent()
    return result

# void _exit(int status);
def exit_handler(mu, status):
    result = 0
    log("exit({})".format(hex(status)))
    inc_indent()
    
    try:
        sys.exit(status)
    except Exception as e:
        log(e)

    dec_indent()
    return result

major_jumps = 0

# int stat(const char *pathname, struct stat *statbuf);
def stat_handler(mu, pathname_addr, statbuf_addr):
    global major_jumps
    result = -1
    pathname = read_string(mu, pathname_addr)
    log("stat({}, {})".format(pathname, hex(statbuf_addr)))
    inc_indent()
    
    try:
        stat_result = os.stat(fs_dir + pathname) # ignore result, only used to check file existence
        #mu.mem_write(statbuf_addr + 0x10, struct.pack("I", 0xA000))
        result = 0
    except Exception as e:
        log(e)

    dec_indent()
    return result

def unpack(fd):
    bin_buf = fd.read()
    elf = ELFFile(fd) # this ruins fd for some reason so that's why we read the data out beforehand
    init_array = elf.get_section_by_name(".init_array")
    unpack_entry = struct.unpack_from("I", init_array.data())[0] # read the first pointer in the .init_array section
    log("Unpack entry point: " + hex(unpack_entry))

    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    allocations = []
    def alloc(size):
        result = alloc.next_base
        mu.mem_map(alloc.next_base, size)
        alloc.next_base += size
        allocations.append(range(result, alloc.next_base))
        return result
    alloc.next_base = emulation_base

    bin_base = alloc(1024 * 1024 * 64) # allocate 64 MB for the binary
    mu.mem_write(bin_base, bin_buf)
    log("Binary loaded at " + hex(bin_base))

    stack_size = 1024 * 1024 * 64 # allocate 64 MB for the stack
    stack_base = alloc(stack_size)
    log("Allocated {} bytes for stack at {}".format(hex(stack_size), hex(stack_base)))

    mu.reg_write(UC_ARM_REG_SP, stack_base + (stack_size // 2))

    def hook_code1(mu, address, size, user_data):
        global major_jumps
        current_pc = mu.reg_read(UC_ARM_REG_PC)
        current_pc_range = None
        last_pc_range = None
        
        for r in allocations:
            if current_pc in r:
                current_pc_range = r
                break

        for r in allocations:
            if hook_code1.last_pc in r:
                last_pc_range = r
                break

        if last_pc_range != current_pc_range:
            log("Jumped from range {}-{} to {}-{} with PC {}".format(hex(last_pc_range.start), hex(last_pc_range.stop), hex(current_pc_range.start), hex(current_pc_range.stop), hex(current_pc)))
            b = mu.mem_read(current_pc_range.start, current_pc_range.stop - current_pc_range.start)
            dump_bytes(b, hex(current_pc_range.start) + "-" + hex(current_pc_range.stop))
            major_jumps += 1

        hook_code1.last_pc = current_pc

        if current_pc == 0x0846235C + emulation_base:
            log("Decrypted string in stage1 {} with return to {} ".format(read_string(mu, mu.reg_read(UC_ARM_REG_R0)), hex(mu.reg_read(UC_ARM_REG_LR))))

        if current_pc in [0x0845BF80]:
            log("thing of " + str(mu.mem_read(mu.reg_read(UC_ARM_REG_R11)-0x14, 4)))
            mu.mem_write(mu.reg_read(UC_ARM_REG_R11)-0x14, struct.pack("I", 1))

        if major_jumps > 0:
            #log("> Instruction at {}".format(hex(address)))
            pass
    hook_code1.last_pc = emulation_base

    def hook_code2(mu, address, size, user_data):
        current_pc = mu.reg_read(UC_ARM_REG_PC)
        if current_pc == 0x0845BF80:
            log("thing of " + str(mu.mem_read(mu.reg_read(UC_ARM_REG_R11)-0x14, 4)))
            mu.mem_write(mu.reg_read(UC_ARM_REG_R11)-0x14, struct.pack("I", 2))


    def hook_intr(mu, intno, user_data):
        if intno == 2: # the interrupt number is always 2 for syscalls
            syscall_number = mu.reg_read(UC_ARM_REG_R7)
            args = [mu.reg_read(reg_idx) for reg_idx in range(UC_ARM_REG_R0, UC_ARM_REG_R6 + 1)]
            
            if syscall_number == 0x5: # int open(const char *pathname, int flags, mode_t mode);
                result = open_handler(mu, *args[0:3])
            elif syscall_number == 0x13: # off_t lseek(int fd, off_t offset, int whence);
                result = lseek_handler(mu, *args[0:3])
            elif syscall_number == 0x3: # ssize_t read(int fd, void *buf, size_t count);
                result = read_handler(mu, *args[0:3])
            elif syscall_number == 0xc0: # void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
                # this syscall is only used as a pseudo-malloc(), we can be lazy with the implementation
                addr, length, prot, flags, fd, offset = args[0:6]
                log("mmap({}, {}, {}, {}, {}, {})".format(hex(addr), hex(length), hex(prot), hex(flags), fd, hex(offset)))
                inc_indent()
                result = alloc(length)
                log("Allocated {} bytes at {}".format(hex(length), hex(result)))
                dec_indent()
            elif syscall_number == 0x6: # int close(int fd);
                result = close_handler(mu, args[0])
            elif syscall_number == 0x5b: # int munmap(void *addr, size_t length);
                result = munmap_handler(mu, *args[0:2])
            elif syscall_number == 0xf0002: # __clear_cache
                result = 0 # let this pass through, it's unnecessary on our faux processor with no instruction cache
                log("__clear_cache({}, {})".format(hex(args[0]), hex(args[1])))
            elif syscall_number == 0x7d: # int mprotect(void *addr, size_t len, int prot);
                result = 0 # let this pass through, all memory has full perms
                log("mprotect({}, {}, {})".format(hex(args[0]), hex(args[1]), hex(args[2])))
            elif syscall_number == 0x1: # void _exit(int status);
                result = exit_handler(mu, args[0])
            elif syscall_number == 0xc3: # int stat(const char *pathname, struct stat *statbuf);
                result = stat_handler(mu, *args[0:2])
            elif syscall_number == 0xc4: # int lstat(const char *pathname, struct stat *statbuf);
                log("lstat", end="")
                result = stat_handler(mu, *args[0:2])
            else:
                log("Exiting! Unhandled syscall number " + hex(syscall_number))
                inc_indent()
                log("Args: " + str(args))
                dec_indent()
                sys.exit(1)

            inc_indent()
            log("Result: " + hex(result))
            dec_indent()
            mu.reg_write(UC_ARM_REG_R0, result)
        else:
            log("Exiting! Unhandled interrupt " + hex(intno))
            sys.exit(1)

    mu.hook_add(UC_HOOK_CODE, hook_code2)
    mu.hook_add(UC_HOOK_INTR, hook_intr)

    entry = bin_base + unpack_entry
    log("Starting emulation at entry " + hex(entry))
    inc_indent()
    mu.emu_start(entry, entry + (4 * 5)) # the end of the unpacking function is five instructions after the entry, each instruction is 4 bytes
    dec_indent()

def main(args):
    print_motd()

    for i in os.listdir(bin_dir):
        log("Unpacking", i)
        inc_indent()

        bin_path = os.path.join(bin_dir, i)
        log("Opening", os.path.abspath(bin_path))
        bin_fd = open(bin_path, "rb")
        unpack(bin_fd)
        bin_fd.close()

        dec_indent()

if __name__ == "__main__":
    main(sys.argv)