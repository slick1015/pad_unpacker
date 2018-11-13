import io
import struct
from elftools.elf.elffile import ELFFile
from emulator import Emulator

def unpack(binary):
    # the unpacking entry point is the first entry in the .init_array section
    # to find it we can just parse the ELF, find the .init_array section, and read the first pointer
    elf = ELFFile(io.BytesIO(binary))
    init_array = elf.get_section_by_name(".init_array")
    unpack_entry = struct.unpack_from("I", init_array.data())[0]

    emu = Emulator(binary)
    unpack_entry += emu.base # correct the entry point to where it is in memory
    emu.start(unpack_entry, unpack_entry + (4 * 5)) # the unpack function ends 5 instructions after entry, each instruction is 4 bytes

    return emu.uc.mem_regions()

if __name__ == "__main__":
    from zipfile import ZipFile
    from argparse import ArgumentParser
    import sys

    parser = ArgumentParser()
    parser.add_argument("binary", help="binary to be unpacked")
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

    unpacked_binary = unpack(binary)
    with open("libpad-unpacked.so", "wb") as f:
        f.write(unpacked_binary)