#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host gtn1.challs.cyberchallenge.it --port 9060
from pwn import *
from typing import Any

# Set up pwntools for the correct architecture
context.update(arch="i386")
exe = "./path/to/binary"

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or "gtn1.challs.cyberchallenge.it"
port = int(args.PORT or 9060)


def start_local(argv: list[str] = [], *a: Any, **kw: Any):
    """Execute the target binary locally"""
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


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
continue
""".format(
    **locals()
)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

io.recvuntil(b"m = ")
m = int(io.recvline())
io.recvuntil(b"c = ")
c = int(io.recvline())
io.recvuntil(b"n = ")
n = int(io.recvline())
io.recvuntil(b"s = ")
s = int(io.recvline())


a = m
x0 = s
x = x0
b = c
n = n


def next() -> int:
    global x
    x = (a * x + b) % n
    return x


for i in range(50):
    io.sendline(str(next()).encode())


# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()
