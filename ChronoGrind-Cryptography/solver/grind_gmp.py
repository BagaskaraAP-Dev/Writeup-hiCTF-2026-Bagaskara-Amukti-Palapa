import sys,struct,hashlib,os,time,gmpy2
d=bytes(b^0x4c for b in open(sys.argv[1],'rb').read())
i=6;recs={}
while i<len(d):
    t=d[i]; l=struct.unpack('<I',d[i+1:i+5])[0]; recs[t]=d[i+5:i+5+l]; i+=5+l
def b241(v):
    n=0
    for c in v: n=n*241+c
    return n
N=gmpy2.mpz(b241(recs[0x11])); s=gmpy2.mpz(b241(recs[0x22])); C=int(recs[0x33]); r66=gmpy2.mpz(b241(recs[0x66]))
ck='ckpt.txt'; done=0; v=s
if os.path.exists(ck):
    a,b=open(ck).read().split(); done=int(a); v=gmpy2.mpz(int(b))
CH=10_000_000; t0=time.time()
while done<C:
    k=min(CH,C-done)
    v=gmpy2.powmod(v,gmpy2.mpz(1)<<k,N); done+=k
    if v==r66: print('HIT r66 at',done,flush=True)
    open(ck+'.tmp','w').write(f'{done} {int(v)}'); os.replace(ck+'.tmp',ck)
    print(done, f'{done/C*100:.2f}%', f'{time.time()-t0:.0f}s',flush=True)
open('v_final.txt','w').write(str(int(v)))
print('DONE',flush=True)
