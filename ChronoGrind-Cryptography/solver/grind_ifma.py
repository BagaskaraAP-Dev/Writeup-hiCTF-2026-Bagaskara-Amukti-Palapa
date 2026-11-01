import sys, struct, subprocess, time, os
NL = 40; RB = 52 * NL; MASK = (1 << 52) - 1
BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ifma')  # compile: gcc -O3 -march=native -o ifma ifma.c

def load(path):
    d = bytes(b ^ 0x4c for b in open(path, 'rb').read())
    i = 6; recs = {}
    while i < len(d):
        t = d[i]; l = struct.unpack('<I', d[i+1:i+5])[0]; recs[t] = d[i+5:i+5+l]; i += 5 + l
    def b241(v):
        n = 0
        for c in v: n = n * 241 + c
        return n
    return b241(recs[0x11]), b241(recs[0x22]), int(recs[0x33])

def limbs(x): return [(x >> (52*j)) & MASK for j in range(NL)]
def unlimbs(l): return sum(v << (52*j) for j, v in enumerate(l))

def run(N, xm, count):
    k0 = (-pow(N, -1, 1 << 52)) % (1 << 52)
    inp = f"{k0} {count}\n" + " ".join(map(str, limbs(N))) + "\n" + " ".join(map(str, limbs(xm))) + "\n"
    out = subprocess.run([BIN], input=inp.encode(), capture_output=True, check=True).stdout
    return unlimbs(list(map(int, out.split())))

if __name__ == '__main__':
    mode = sys.argv[1]
    N, s, C = load(sys.argv[2])
    R = 1 << RB
    if mode == 'test':
        k = int(sys.argv[3])
        t = time.time(); xm = run(N, s * R % N, k); dt = time.time() - t
        got = xm * pow(R, -1, N) % N
        exp = pow(s, 1 << k, N)
        print('OK' if got == exp else 'MISMATCH', f'{dt/k*1e6:.3f} us/sq')
    elif mode == 'grind':
        # resume from GMP checkpoint (done, v) and continue with IFMA
        ck = sys.argv[3]; out = sys.argv[4]
        done, v = map(int, open(ck).read().split())
        xm = v * R % N
        CH = 200_000_000; t0 = time.time()
        while done < C:
            k = min(CH, C - done)
            xm = run(N, xm, k); done += k
            v = xm * pow(R, -1, N) % N
            open(out + '.tmp', 'w').write(f'{done} {v}'); os.replace(out + '.tmp', out)
            print(done, f'{done/C*100:.2f}%', f'{time.time()-t0:.0f}s', flush=True)
        open(out + '.final', 'w').write(str(v))
        print('DONE', flush=True)
