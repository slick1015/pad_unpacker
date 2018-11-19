pad_unpacker - Puzzle and Dragons binary unpacker
=================================================
pad_unpacker is a tool for unpacking shared objects in the Puzzle and Dragons' APK. Unpacking is done through emulation using [Unicorn](https://github.com/unicorn-engine/unicorn/).

# Usage
```
usage: pad_unpack.py [-h] [-l LIB_PATH] binary

positional arguments:
  binary                binary to be unpacked, .apk or .so

optional arguments:
  -h, --help            show this help message and exit
  -l LIB_PATH, --lib_path LIB_PATH
                        path to the library in the apk to be unpacked
```