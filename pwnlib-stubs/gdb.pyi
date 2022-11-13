from pwnlib.tubes.process import process

class Gdb: ...

class _gdb_process(process):
    gdb: Gdb

def debug(args: list[str], gdbscript: str = ..., api: bool = ...) -> _gdb_process: ...
def attach(io: process | int | str | tuple[str, int], gdbscript: str = ...) -> int: ...
