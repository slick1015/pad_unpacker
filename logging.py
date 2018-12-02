MOTD = "PaD Unpacker for Version 15.3.0 - MrSlick"

_indent_level = 0
debug_out = open("./pad_unpacker_log.txt", "w")

def log(*args, end=None):
    print("\t" * _indent_level, end="")
    print("\t" * _indent_level, end="", file=debug_out)
    if end != None:
        print(*args, end=end)
        print(*args, end=end, file=debug_out)
    else:
        print(*args)
        print(*args, file=debug_out)

# logging increase indent
def linc():
    global _indent_level
    _indent_level += 1

# logging decrease indent
def ldec():
    global _indent_level
    _indent_level -= 1

def print_motd():
    log("-" * len(MOTD))
    log(MOTD)
    log("-" * len(MOTD))