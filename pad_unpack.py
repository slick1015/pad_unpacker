import io
import struct
from elftools.elf.elffile import ELFFile
from emulator import Emulator
from logging import *
from vfs import write_vfs_libpad

def unpack(binary):
    # the virtual filesystem needs a copy of the binary 
    # so the binary can parse itself during unpacking
    write_vfs_libpad(binary)


    # the unpacking entry point is the first entry in the .init_array section
    # to find it we can just parse the ELF, find the .init_array section, and read the first pointer
    elf = ELFFile(io.BytesIO(binary))
    init_array = elf.get_section_by_name(".init_array")
    unpack_entry = struct.unpack_from("I", init_array.data())[0]
    log("Unpacking entry point offset at {:#010x}".format(unpack_entry))
    
    emu = Emulator()

    # load each segment into memory
    for seg in elf.iter_segments():
        h = seg.header
        emu.uc.mem_write(emu.bin_base + h["p_vaddr"], binary[h["p_offset"] : h["p_offset"] + h["p_filesz"]])

    unpack_entry += emu.base # correct the entry point to where it is in memory
    emu.start(unpack_entry, unpack_entry + (4 * 5)) # the unpack function ends 5 instructions after entry, each instruction is 4 bytes

    unpacked_begin, unpacked_end, unpacked_perms = emu.allocations()[0] # the first allocation holds the original binary

    # TODO: there will probably need to be more processing on the final binary
    return emu.uc.mem_read(unpacked_begin, unpacked_end) # we only want as many bytes as the size of the original binary

if __name__ == "__main__":
    from zipfile import ZipFile
    from argparse import ArgumentParser
    import sys

    print_motd()

    parser = ArgumentParser()
    parser.add_argument("binary", help="binary to be unpacked, .apk or .so")
    parser.add_argument("-l", "--lib_path", help="path to the library in the apk to be unpacked", default="lib/armeabi/libpad.so")
    args = parser.parse_args()

    if args.binary.endswith(".apk"):
        with ZipFile(args.binary) as zf:
            if args.lib_path in zf.namelist():
                binary = bytes(zf.read(args.lib_path))
            else:
                print("invalid lib_path, not found in APK")
                sys.exit(1)
    else:
        with open(args.binary, "rb") as f:
            binary = f.read()

    log("Unpacking binary...")
    linc()
    unpacked_binary = unpack(binary)
    ldec()
    log("Writing unpacked binary...")
    with open("libpad-unpacked.so", "wb") as f:
        f.write(unpacked_binary)