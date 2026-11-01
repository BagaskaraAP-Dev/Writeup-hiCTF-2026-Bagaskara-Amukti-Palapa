import sys,hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
v=int(open(sys.argv[1]).read())
f=open(sys.argv[2],'rb').read()
assert f[:4]==b'CGFX'; nonce=f[5:17]; tag=f[17:33]; ct=f[33:]
k=hashlib.sha256(v.to_bytes(256,'big')).digest()
print(ChaCha20Poly1305(k).decrypt(nonce,ct+tag,None))
