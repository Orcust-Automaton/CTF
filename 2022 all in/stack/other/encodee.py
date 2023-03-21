from z3 import *

a = 0x61616161

for i in range(10):
    a ^= LShR((a ^ (48 * a)), 21) ^ (48 * a) ^ ((a ^ (48 * a) ^ LShR((a ^ (48 * a)) , 21)) << 17)

print(a)