from z3 import *

solver = Solver()

b = BitVecVal(0x1607cd48 ,32)

ptr = [BitVec("ptr[%d]" % i,32) for i in range(11)]
solver.add(ptr[1] == ((LShR(ptr[0] ^ (48 * ptr[0]),21)) ^ (48 * ptr[0]) ^ ((ptr[0] ^ (48 * ptr[0]) ^ (LShR(ptr[0] ^ (48 * ptr[0]),21))) << 17)) ^ ptr[0])
solver.add(ptr[2] == ((LShR(ptr[1] ^ (48 * ptr[1]),21)) ^ (48 * ptr[1]) ^ ((ptr[1] ^ (48 * ptr[1]) ^ (LShR(ptr[1] ^ (48 * ptr[1]),21))) << 17)) ^ ptr[1])
solver.add(ptr[3] == ((LShR(ptr[2] ^ (48 * ptr[2]),21)) ^ (48 * ptr[2]) ^ ((ptr[2] ^ (48 * ptr[2]) ^ (LShR(ptr[2] ^ (48 * ptr[2]),21))) << 17)) ^ ptr[2])
solver.add(ptr[4] == ((LShR(ptr[3] ^ (48 * ptr[3]),21)) ^ (48 * ptr[3]) ^ ((ptr[3] ^ (48 * ptr[3]) ^ (LShR(ptr[3] ^ (48 * ptr[3]),21))) << 17)) ^ ptr[3])
solver.add(ptr[5] == ((LShR(ptr[4] ^ (48 * ptr[4]),21)) ^ (48 * ptr[4]) ^ ((ptr[4] ^ (48 * ptr[4]) ^ (LShR(ptr[4] ^ (48 * ptr[4]),21))) << 17)) ^ ptr[4])
solver.add(ptr[6] == ((LShR(ptr[5] ^ (48 * ptr[5]),21)) ^ (48 * ptr[5]) ^ ((ptr[5] ^ (48 * ptr[5]) ^ (LShR(ptr[5] ^ (48 * ptr[5]),21))) << 17)) ^ ptr[5])
solver.add(ptr[7] == ((LShR(ptr[6] ^ (48 * ptr[6]),21)) ^ (48 * ptr[6]) ^ ((ptr[6] ^ (48 * ptr[6]) ^ (LShR(ptr[6] ^ (48 * ptr[6]),21))) << 17)) ^ ptr[6])
solver.add(ptr[8] == ((LShR(ptr[7] ^ (48 * ptr[7]),21)) ^ (48 * ptr[7]) ^ ((ptr[7] ^ (48 * ptr[7]) ^ (LShR(ptr[7] ^ (48 * ptr[7]),21))) << 17)) ^ ptr[7])
solver.add(ptr[9] == ((LShR(ptr[8] ^ (48 * ptr[8]),21)) ^ (48 * ptr[8]) ^ ((ptr[8] ^ (48 * ptr[8]) ^ (LShR(ptr[8] ^ (48 * ptr[8]),21))) << 17)) ^ ptr[8])
solver.add(ptr[10] == ((LShR(ptr[9] ^ (48 * ptr[9]),21)) ^ (48 * ptr[9]) ^ ((ptr[9] ^ (48 * ptr[9]) ^ (LShR(ptr[9] ^ (48 * ptr[9]),21))) << 17)) ^ ptr[9])

solver.add( ptr[10] == b)

if solver.check() == sat:
    m = solver.model()
    for d in m.decls():
        print("%s = %s" % (d.name(), m[d]))