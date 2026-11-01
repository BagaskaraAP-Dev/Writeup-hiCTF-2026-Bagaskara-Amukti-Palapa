import sys,struct,hashlib
d=bytes(b^0x4c for b in open(sys.argv[1],'rb').read())
print(d[:5])
i=6
recs={}
while i<len(d):
    t=d[i]; l=struct.unpack('<I',d[i+1:i+5])[0]; v=d[i+5:i+5+l]; i+=5+l
    recs[t]=v
    print(hex(t),l, v[:40], 'max',max(v))
def b241(v):
    n=0
    for c in v: n=n*241+c
    return n
for t in (0x11,0x22,0x66):
    print(hex(t), b241(recs[t]).bit_length(), b241(recs[t]))
print(recs[0x88].hex(), recs[0x44].hex())
N=b241(recs[0x11]); s=b241(recs[0x22]); c=int(recs[0x33]); r66=b241(recs[0x66])
print('chk', hashlib.sha256(f'{N}:{s}:{c}'.encode()).hexdigest()[:16], recs[0x44].hex())
import gmpy2
print('N prime?', gmpy2.is_prime(N))
from math import gcd, isqrt
print('gcd', gcd(N,r66), gcd(N,s))
a=gmpy2.isqrt(N)+1
for _ in range(100000):
    b2=a*a-N
    if gmpy2.is_square(b2): print('fermat!',a); break
    a+=1
v=s
for k in range(1,1<<20):
    v=v*v%N
    if v==r66: print('r66 = s^(2^%d)'%k); break
