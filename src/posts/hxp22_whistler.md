---
title: "Whistler, hxp ctf 2022"
description: "Writeup of whistler from hxp ctf 2022"
date: 2024-03-29
tags:  [Crypto, LLL, Enumeration]
eleventyNavigation:
  key: hxp2022
  parent: Writeups
---


## Overview

Although I solved this challenge during competition, about two years ago, it was the first time I played in person with my team mates, so I decided to have this writeup as the first post for "sentimental reasons":).


### Description:

```
Descriptions are hard, but are decryptions?
```

### Source:

```python

#!/usr/bin/env python3
import struct, hashlib, random, os
from Crypto.Cipher import AES

n = 256
q = 11777
w = 8

################################################################

sample = lambda rng: [bin(rng.getrandbits(w)).count('1') - w//2 for _ in range(n)]

add = lambda f,g: [(x + y) % q for x,y in zip(f,g)]

def mul(f,g):
    r = [0]*n
    for i,x in enumerate(f):
        for j,y in enumerate(g):
            s,k = divmod(i+j, n)
            r[k] += (-1)**s * x*y
            r[k] %= q
    return r

################################################################

def genkey():
    a = [random.randrange(q) for _ in range(n)]
    rng = random.SystemRandom()
    s,e = sample(rng), sample(rng)
    b = add(mul(a,s), e)
    return s, (a,b)

center = lambda v: min(v%q, v%q-q, key=abs)
extract = lambda r,d: [2*t//q for u,t in zip(r,d) if u]

ppoly = lambda g: struct.pack(f'<{n}H', *g).hex()
pbits = lambda g: ''.join(str(int(v)) for v in g)
hbits = lambda g: hashlib.sha256(pbits(g).encode()).digest()
mkaes = lambda bits: AES.new(hbits(bits), AES.MODE_CTR, nonce=b'')

def encaps(pk):
    seed = os.urandom(32)
    rng = random.Random(seed)
    a,b = pk
    s,e = sample(rng), sample(rng)
    c = add(mul(a,s), e)
    d = add(mul(b,s), e)
    r = [int(abs(center(2*v)) > q//7) for v in d]
    bits = extract(r,d)
    return bits, (c,r)

def decaps(sk, ct):
    s = sk
    c,r = ct
    d = mul(c,s)
    return extract(r,d)

################################################################

if __name__ == '__main__':

    while True:
        sk, pk = genkey()
        dh, ct = encaps(pk)
        if decaps(sk, ct) == dh:
            break

    print('pk[0]:', ppoly(pk[0]))
    print('pk[1]:', ppoly(pk[1]))

    print('ct[0]:', ppoly(ct[0]))
    print('ct[1]:', pbits(ct[1]))

    flag = open('flag.txt').read().strip()
    print('flag: ', mkaes([0]+dh).encrypt(flag.encode()).hex())

    for _ in range(2048):
        c = list(struct.unpack(f'<{n}H', bytes.fromhex(input())))
        r = list(map('01'.index, input()))
        if len(r) != n or sum(r) < n//2: exit('!!!')

        bits = decaps(sk, (c,r))

        print(mkaes([1]+bits).encrypt(b'hxp<3you').hex())

```

### SOLUTION

Notice the 3 main values: 

* `n`, the degree of the polynomial ring we're working over, namely $R_q = (ZZ/qZZ)[x]/(x^n + 1)$
* `q`, the order of the prime field the polynomials are defined over
* `w`, the width of the binomial distirbution we'll sample coefficients from

On line 11, we have:

```python
sample = lambda rng: [bin(rng.getrandbits(w)).count('1') - w//2 for _ in range(n)] 
```

This is the centered binomial distribution sampler. It samples `w` random bits and counts the number of '1's, then subtracts `w/2` to center the distribution around zero.

It's also important to note that polynomials are represented here as lists of 256 coefficients, since in $R_q$ we have that $x^{256} = -1$. 

My attack consisted of 2 steps:

* 1: collecting data for each `c`

    Collect and save "side choices" for values of `c`, where `c` is a constant polynomial
    Let `d = cs`. Assuming `d[0] < q/2`, we do all the encrypted message comparisons to figure out which side of q/2 each coefficient is on.

```python
    c = ppoly([0]*128+[1]+[0]*127)
    c = ppoly([1]+[0]*255)
    c = ppoly([0]*128+[q//4+1]+[0]*127)
    c = ppoly([q//4+1]+[0]*255)
    c = ppoly([0]*128+[q//2+1]+[0]*127)
    c = ppoly([q//2+1]+[0]*255)
    c = ppoly([0]*128+[q//8+1]+[0]*127)
    c = ppoly([q//8+1]+[0]*255)

```

*  2: enumerating the possibilities for `d[0]` and getting `s`

    Since `d[0] < q/2` may be false for some values of `c`, we iterate over every possible combination of side choices that need to be flipped versus which don't and use these guesses to try to determine each coefficient of `s`.
    

### Solve Script

My exploit during the competition was really messy, but I don't wanna mess it up by fixing it so much time after the competition, so here goes nothing:


```python

import struct, hashlib, random, os
from Crypto.Cipher import AES
from pwn import *

n = 256
q = 11777
w = 8

sample = lambda rng: [bin(rng.getrandbits(w)).count('1') - w//2 for _ in range(n)]

add = lambda f,g: [(x + y) % q for x,y in zip(f,g)]

def mul(f,g):
    r = [0]*n
    for i,x in enumerate(f):
        for j,y in enumerate(g):
            s,k = divmod(i+j, n)
            r[k] += (-1)**s * x*y
            r[k] %= q
    return r

def genkey():
    a = [random.randrange(q) for _ in range(n)]
    rng = random.SystemRandom()
    s,e = sample(rng), sample(rng)
    b = add(mul(a,s), e)
    return s, (a,b)

center = lambda v: min(v%q, v%q-q, key=abs)
extract = lambda r,d: [2*t//q for u,t in zip(r,d) if u]

ppoly = lambda g: struct.pack(f'<{n}H', *g).hex()
ppolyrev = lambda g: list(struct.unpack(f'<{n}H', bytes.fromhex(g)))


pbits = lambda g: ''.join(str(int(v)) for v in g)
pbitsinv = lambda g: list(map('01'.index, g))

hbits = lambda g: hashlib.sha256(pbits(g).encode()).digest()
mkaes = lambda bits: AES.new(hbits(bits), AES.MODE_CTR, nonce=b'')

def encaps(pk):
    seed = os.urandom(32)
    rng = random.Random(seed)
    a,b = pk
    s,e = sample(rng), sample(rng)
    c = add(mul(a,s), e)
    d = add(mul(b,s), e)
    r = [int(abs(center(2*v)) > q//7) for v in d]
    bits = extract(r,d)
    return bits, (c,r)

def decaps(sk, ct):
    s = sk
    c,r = ct
    d = mul(c,s)
    return extract(r,d)

remote = remote('116.203.41.47', 4421)

pk = [0,0]
ct = [0,0]


pk[0] = (remote.recvline()[7:-1]).decode()
pk[1] = (remote.recvline()[7:-1]).decode()
pk[0] = list(struct.unpack(f'<{n}H', bytes.fromhex(pk[0])))
pk[1] = list(struct.unpack(f'<{n}H', bytes.fromhex(pk[1])))

ct[0] = (remote.recvline()[7:-1]).decode()
ct[1] = (remote.recvline()[7:-1]).decode()

c = list(struct.unpack(f'<{n}H', bytes.fromhex(ct[0]))) 
r = list(map('01'.index, ct[1])) 

flag = remote.recvline()[6:-1].decode()

"""
key = ['' for _ in range(256)]
txt = b'hxp<3you'
test0 = (mkaes([1]+[0]+[0]*255).encrypt(b'hxp<3you').hex())
test1 = (mkaes([1]+[1]+[0]*255).encrypt(b'hxp<3you').hex())

c1 = ppoly([1]+[0]*255)
c2 = ppoly([q//4+1]+[q]*255)
c3 = ppoly([q//2+1]+[q]*255)
c4 = ppoly([q//8+1]+[q]*255)
"""

c = ppoly([0]*128+[1]+[0]*127)
eq11 = []
neq11 = []
r = pbits([1]*(n//2) + [0]*(n//2))
remote.sendline(c)
remote.sendline(r)
ref = (remote.recvline())
for i in range(128,256):
    r = pbits([1]*127 + [0]*(i-127) + [1] + [0]*(256-i-1))
    remote.sendline(c)
    remote.sendline(r)
    txt = (remote.recvline())
    if txt==ref:
        eq11.append(i-128)
    else:
        neq11.append(i-128)

c = ppoly([1]+[0]*255)
eq12 = []
neq12 = []
r = pbits([1]*(n//2) + [0]*(n//2))
remote.sendline(c)
remote.sendline(r)
ref = (remote.recvline())
for i in range(128,256):
    r = pbits([1]*127 + [0]*(i-127) + [1] + [0]*(256-i-1))
    remote.sendline(c)
    remote.sendline(r)
    txt = (remote.recvline())
    if txt==ref:
        eq12.append(i)
    else:
        neq12.append(i)

c = ppoly([0]*128+[q//4+1]+[0]*127)
eq21 = []
neq21 = []
r = pbits([1]*(n//2) + [0]*(n//2))
remote.sendline(c)
remote.sendline(r)
ref = (remote.recvline())
for i in range(128,256):
    r = pbits([1]*127 + [0]*(i-127) + [1] + [0]*(256-i-1))
    remote.sendline(c)
    remote.sendline(r)
    txt = (remote.recvline())
    if txt==ref:
        eq21.append(i-128)
    else:
        neq21.append(i-128)

c = ppoly([q//4+1]+[0]*255)
eq22 = []
neq22 = []
r = pbits([1]*(n//2) + [0]*(n//2))
remote.sendline(c)
remote.sendline(r)
ref = (remote.recvline())
for i in range(128,256):
    r = pbits([1]*127 + [0]*(i-127) + [1] + [0]*(256-i-1))
    remote.sendline(c)
    remote.sendline(r)
    txt = (remote.recvline())
    if txt==ref:
        eq22.append(i)
    else:
        neq22.append(i)

c = ppoly([0]*128+[q//2+1]+[0]*127)
eq31 = []
neq31 = []
r = pbits([1]*(n//2) + [0]*(n//2))
remote.sendline(c)
remote.sendline(r)
ref = (remote.recvline())
for i in range(128,256):
    r = pbits([1]*127 + [0]*(i-127) + [1] + [0]*(256-i-1))
    remote.sendline(c)
    remote.sendline(r)
    txt = (remote.recvline())
    if txt==ref:
        eq31.append(i-128)
    else:
        neq31.append(i-128)

c = ppoly([q//2+1]+[0]*255)
eq32 = []
neq32 = []
r = pbits([1]*(n//2) + [0]*(n//2))
remote.sendline(c)
remote.sendline(r)
ref = (remote.recvline())
for i in range(128,256):
    r = pbits([1]*127 + [0]*(i-127) + [1] + [0]*(256-i-1))
    remote.sendline(c)
    remote.sendline(r)
    txt = (remote.recvline())
    if txt==ref:
        eq32.append(i)
    else:
        neq32.append(i)

c = ppoly([0]*128+[q//8+1]+[0]*127)
eq41 = []
neq41 = []
r = pbits([1]*(n//2) + [0]*(n//2))
remote.sendline(c)
remote.sendline(r)
ref = (remote.recvline())
for i in range(128,256):
    r = pbits([1]*127 + [0]*(i-127) + [1] + [0]*(256-i-1))
    remote.sendline(c)
    remote.sendline(r)
    txt = (remote.recvline())
    if txt==ref:
        eq41.append(i-128)
    else:
        neq41.append(i-128)

c = ppoly([q//8+1]+[0]*255)
eq42 = []
neq42 = []
r = pbits([1]*(n//2) + [0]*(n//2))
remote.sendline(c)
remote.sendline(r)
ref = (remote.recvline())
for i in range(128,256):
    r = pbits([1]*127 + [0]*(i-127) + [1] + [0]*(256-i-1))
    remote.sendline(c)
    remote.sendline(r)
    txt = (remote.recvline())
    if txt==ref:
        eq42.append(i)
    else:
        neq42.append(i)

print(eq11)
print(neq11)
print(eq12)
print(neq12)
print(eq21)
print(neq21)
print(eq22)
print(neq22)
print(eq31)
print(neq31)
print(eq32)
print(neq32)
print(eq41)
print(neq41)
print(eq42)
print(neq42)
print(ct)
print(pk)
print(flag)

```

For part 2, I wrote a simple script using itertools to test the combinations.

**Flag: `hxp{e4zy_p34zY_p34nuT_Bu7t3r}`**