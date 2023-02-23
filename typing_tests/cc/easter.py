from pwnlib.elf import ELF

elf = ELF("easter_egg")

base = 0x004008F2
for i in range(376):
    x1 = (42 + i) % 256
    elf.write(base + i, bytes([elf.read(base + i, 1)[0] ^ x1]))
elf.save("output")
