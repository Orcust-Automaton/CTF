import os
import hashlib


while True:
    md5 = hashlib.md5()
    key = os.urandom(0x20)
    md5.update(key)
    res = md5.hexdigest()
    if res[:2] == "00":
        print("find: ", res, key) 
        break
