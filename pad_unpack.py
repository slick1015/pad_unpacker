import io
import struct
from elftools.elf.elffile import ELFFile
from emulator import Emulator
from logging import *

def unpack(binary):
    # the unpacking entry point is the first entry in the .init_array section
    # to find it we can just parse the ELF, find the .init_array section, and read the first pointer
    elf = ELFFile(io.BytesIO(binary))
    init_array = elf.get_section_by_name(".init_array")
    unpack_entry = struct.unpack_from("I", init_array.data())[0]
    log("Unpacking entry point offset at {:#010x}".format(unpack_entry))

    emu = Emulator(binary)
    unpack_entry += emu.base # correct the entry point to where it is in memory
    emu.start(unpack_entry, unpack_entry + (4 * 5)) # the unpack function ends 5 instructions after entry, each instruction is 4 bytes

    unpacked_begin, unpacked_end, unpacked_perms = emu.allocations()[0] # the first allocation holds the original binary

    return emu.uc.mem_read(unpacked_begin, len(binary)) # we only want as many bytes as the size of the original binary

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