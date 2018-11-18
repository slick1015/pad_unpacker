MOTD = "PaD Unpacker for Version 15.3.0 - MrSlick"
_indent_level = 0

def log(*args, end=None):
    print("\t" * _indent_level, end="")
    if end != None:
        print(*args, end=end)
    else:
        print(*args)

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