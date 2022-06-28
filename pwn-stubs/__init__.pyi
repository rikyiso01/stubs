from pwnlib.context import context
from pwnlib.tubes.process import process
from pwnlib.tubes.remote import connect, remote
from pwnlib.tubes.ssh import ssh
import pwnlib.gdb as gdb
from pwnlib.elf import ELF
from pwnlib.util.cyclic import cyclic, cyclic_find
from pwnlib.util.packing import (
    p8,
    p16,
    p32,
    p64,
    u8,
    u16,
    u32,
    u64,
    pack,
    unpack,
    fit,
    flat,
)
import pwnlib.shellcraft as shellcraft
from pwnlib.asm import asm, disasm
import pwnlib.log as log
from pwnlib.fiddling import (
    b64d,
    b64e,
    rol,
    ror,
    unhex,
    enhex,
    xor,
    urldecode,
    urlencode,
    bits,
    unbits,
)
from pwnlib.fmtstr import FmtStr, fmtstr_payload
import os
import sys
import time
import requests
import re
import random

class _Args:
    def __getitem__(self, key: str) -> str: ...
    def __getattr__(self, key: str) -> str: ...

args: _Args

__all__ = [
    "context",
    "args",
    "process",
    "gdb",
    "connect",
    "ELF",
    "p8",
    "p16",
    "p32",
    "p64",
    "u8",
    "u16",
    "u32",
    "u64",
    "pack",
    "unpack",
    "shellcraft",
    "asm",
    "disasm",
    "log",
    "ssh",
    "remote",
    "b64d",
    "b64e",
    "rol",
    "ror",
    "unhex",
    "enhex",
    "xor",
    "urldecode",
    "urlencode",
    "bits",
    "unbits",
    "os",
    "sys",
    "time",
    "requests",
    "re",
    "random",
    "fit",
    "flat",
    "cyclic",
    "cyclic_find",
    "FmtStr",
    "fmtstr_payload",
]
