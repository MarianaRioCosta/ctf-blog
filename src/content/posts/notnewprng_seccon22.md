---
title: Not New PRNG, SECCON ﬁnals 2022
published: 2024-03-30
description: Writeup of Not New PRNG from SECCON ﬁnals 2022
tags: [CTF, LLL, Enumeration]
category: 'Crypto'
draft: false 
---

### Description:

```
Recently, I learned that this random number generator is called "MRG".
```

### Source:

```python
import os
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime


p = getPrime(128)

xs = [random.randint(1, 2**64) for _ in range(4)]

a = random.randint(1, p)
b = random.randint(1, p)
c = random.randint(1, p)
d = random.randint(1, p)
e = random.randint(1, p)  # unknown

xs.append((a*xs[-4] + b*xs[-3] + c*xs[-2] + d*xs[-1] + e) % p)
xs.append((a*xs[-4] + b*xs[-3] + c*xs[-2] + d*xs[-1] + e) % p)
xs.append((a*xs[-4] + b*xs[-3] + c*xs[-2] + d*xs[-1] + e) % p)

outs = xs[-3:]


# encryption
FLAG = os.getenv("FLAG", "fake{the_flag_is_a_lie}")
key = 0
for x in xs[:4]:
    key <<= 64
    key += x
key = int(key).to_bytes(32, "little")
iv = get_random_bytes(16)  # public
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pad(FLAG.encode(), 16))  # public

# output
print(f"p = {p}")
print(f"a = {a}")
print(f"b = {b}")
print(f"c = {c}")
print(f"d = {d}")
print(f"outs = {outs}")
print(f"iv = 0x{iv.hex()}")
print(f"ct = 0x{ct.hex()}")

```

### SOLUTION

Finding the lattice for this challenge was not hard, but i found it a good way to practice enumeration.

From the source, I took out the following equations:

* $x_4 = a x_0 + b x_1 + c x_2 + d x_3 + e \pmod p$

* $x_5 = a x_1 + b x_2 + c x_3 + d x_4 + e \pmod p$

* $x_6 = a x_2 + b x_3 + c x_4 + d x_5 + e \pmod p$

Where $a,b,c,d, x_4, x_5, x_6, p$ are known.

By expanding the equations above on the known terms (and $e$), we have:

* $x_4 = a x_0 + b x_1 + c x_2 + d x_3 + e \pmod p$

* $x_5 = ad x_0 + (a + bd) x_1 + (b + cd) x_2 + (c + d^2) x_3 + (1 + d) e \pmod p$

* $x_6 = (ca + ad^2) x_0 + (cb + d(a + bd)) x_1 + (a + c^2 + d(b + cd)) x_2 + (b + cd + d(c + d^2)) x_3 + (1 + c + d(1 + d)) e \pmod p$

Now, we can remove $e$ from these expressions by calculating:

* $x_5 - (d+1)*x_4 \pmod p$

* $x_6 - (d^2+c+d+1)*x_4 \pmod p$

* $x_6 - x_5 - (d^2+c)*x_4 \pmod p$

Since we know $a,b,c,d, x_4, x_5, x_6, p$, we can calculate the value of each expression.
This will result in a system of equations with 4 variables and 3 equations, and therefore it has more than one solution. Whatever, all our variables have values between 1 and $2^{64}$.

We can then use the result and coefficients of $x_0, x_1, x_2, x_3$ in each equation to generate the lattice for our problem.

My first try was using `LLL`, but that was not enough to get the solution I was looking for. 

After spending some time reading the [fpylll documentation](https://github.com/fplll/fpylll), I finally managed to enumerate the lattice vectors and get the one I was looking for.


## Solve Script

```python

import random
import numpy as np
from Crypto.Util.number import isPrime, getPrime
from itertools import product
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from fpylll import IntegerMatrix, LLL
from fpylll.fplll.gso import MatGSO
from fpylll.fplll.enumeration import Enumeration

p = 234687789984662131107323206406195107369
a = 35686285754866388325178539790367732387
b = 36011211474181220344603698726947017489
c = 84664322357902232989540976252462702046
d = 154807718022294938130158404283942212610
outs = [222378874028969090293268624578715626424, 42182082074667038745014860626841402403, 217744703567906139265663577111207633608]
iv = bytes.fromhex('f2dd287ca870eb9908bf52c44dfd9d2b')
ct = bytes.fromhex('236a6aca059ae29056a23f5458c644abb74640d672dba1ee049eb956e629b7afb03ae33b2b2b419c24197d33baf6d88e2f0eedfa90c06e1a2be18b2fae2270f05ce39de5e0d59bb9a442d1b3eb392658e45cf721094543b13d35df8cf9ce420c')

"""
#F = Zmod(p)
kxs = [var(f"xs{i}") for i in range(4)]
e = var(f'e')

kxs += [(a*kxs[-4] + b*kxs[-3] + c*kxs[-2] + d*kxs[-1] + e)]
kxs += [(a*kxs[-4] + b*kxs[-3] + c*kxs[-2] + d*kxs[-1] + e)]
kxs += [(a*kxs[-4] + b*kxs[-3] + c*kxs[-2] + d*kxs[-1] + e)]

xs = [kxs[0],
 kxs[1],
 kxs[2],
 kxs[3],
 e + (35686285754866388325178539790367732387%p)*kxs[0] + (36011211474181220344603698726947017489%p)*kxs[1] + (84664322357902232989540976252462702046%p)*kxs[2] + (154807718022294938130158404283942212610%p)*kxs[3],
 (154807718022294938130158404283942212611%p)*e + (5524512462402396504522631022186993689941902586904182387956969847513136800070%p)*kxs[0] + (5574813471536278371812192944436468893673412103510013549372682471857394068677%p)*kxs[1] + (13106690542130809785016373593585159951283185043634670521563223863167361017549%p)*kxs[2] + (23965429559270380990259083357664627080454574539545585116705269958114905714146%p)*kxs[3],
 (23965429559270380990259083357664627080609382257567880054835428362398847926757%p)*e + (855237167490244464144875675573572867629762831370918736738696909377997562042125797695788728304700411167882848246502%p)*kxs[0] + (863024151928479330388076030989990627721702706923244759964245940344901793434930274712611324824222143408391433499464%p)*kxs[1] + (2029016853651666375038394107112295102356624289908454784624904137323194978538243016927915014578940870109681839411393%p)*kxs[2] + (3710033461494701195379191462199896884427637415170375363625339494855060676724077241776127864987795159943314777598609%p)*kxs[3]]


#[xs0, xs1, xs2, xs3, e + 35686285754866388325178539790367732387*xs0 + 36011211474181220344603698726947017489*xs1 + 84664322357902232989540976252462702046*xs2 + 154807718022294938130158404283942212610*xs3, 154807718022294938130158404283942212611*e + 24233268721794315913299373990028841403*xs0 + 83801899324939637851561928647683080672*xs1 + 124789883491551059250886060798635202617*xs2 + 117261698239628161615415951256878674368*xs3, 37381626277260968638251149134625779610*e + 27700972286058499906845172507055534594*xs0 + 174414886418714913984767195293981001560*xs1 + 68655552639519520906718520656801969746*xs2 + 125049678834442576080997917331138548268*xs3]
"""

A = []
A+=[[35686285754866388325178539790367732387,36011211474181220344603698726947017489,84664322357902232989540976252462702046,154807718022294938130158404283942212610]]
A+=[[24233268721794315913299373990028841403,83801899324939637851561928647683080672,124789883491551059250886060798635202617,117261698239628161615415951256878674368]]
A+=[[27700972286058499906845172507055534594,174414886418714913984767195293981001560,68655552639519520906718520656801969746,125049678834442576080997917331138548268]]

A = Matrix(A)
E = vector([1,154807718022294938130158404283942212611,37381626277260968638251149134625779610])


#here, we have Ax + eE = B, we can "remove" the e 

F = Zmod(p)
xs = [var(f"xs{i}") for i in range(4)]
kxs = [x for x in xs]
e = var(f'e')

kxs += [(a*kxs[-4] + b*kxs[-3] + c*kxs[-2] + d*kxs[-1] + e)]
kxs += [(a*kxs[-4] + b*kxs[-3] + c*kxs[-2] + d*kxs[-1] + e)]
kxs += [(a*kxs[-4] + b*kxs[-3] + c*kxs[-2] + d*kxs[-1] + e)]

x4=kxs[4]
x5=kxs[5]
x6=kxs[6]


f1 = x5 - (d+1)*x4
out3 = (outs[1] - (d+1)*outs[0]) % p

f2 = x6 - (d^2+c+d+1)*x4
out4 = (outs[2] - (d^2+c+d+1)*outs[0]) % p

f3 = x6 - x5 - (d^2+c)*x4
out5 = (outs[2] - outs[1] - (d^2+c)*outs[0]) % p

line1 = [F(f1.coefficient(x)) for x in xs]
line2 = [F(f2.coefficient(x)) for x in xs]
line3 = [F(f3.coefficient(x)) for x in xs]

A = Matrix([line1,line2,line3])
B = vector([out3,out4,out5])



def enumerator(B, matrix, p, bound):
    n = len(B)
    m = len(matrix[0])
    L = [
        [0 for _ in range(n+m)] for _ in range(n+m)
    ]
    for i in range(n):
        L[i][i] = p

    for i in range(m-1):
        L[n+i][n+i] = 1

    L[-1][-1] = bound

    for i, (y, coeff) in enumerate(zip(B, matrix)):
        a_inv = coeff[0]^-1
        constant = y*a_inv 
        _coeff = [-v * a_inv for v in coeff][1:] + [constant]

        for j, x in enumerate(_coeff):
            L[j+n][i] = int(x)

    sols = []

    A = IntegerMatrix.from_matrix(L)
    LLL.reduction(A)
    M = MatGSO(A)
    M.update_gso()

    sol_nr = 1000
    enum = Enumeration(M, sol_nr)
    answers = enum.enumerate(0, n+m, (n+m * bound**2), 0, pruning=None)

    for _, s in answers:
        v = IntegerMatrix.from_iterable(1, A.nrows, map(int, s))
        newsol = v * A

        if abs(newsol[0, n+m-1]) == bound:
            sig = 1 if newsol[0, n+m-1] == bound else -1
            newsol = [sig*x for x in newsol[0]]
            ok = True
            for x in newsol:
                if x < 0:
                    ok = False
                    break
            if not ok:
                continue

            if len(set(newsol[:n])) != 1:
                continue

            sols.append([newsol[0]] + newsol[n:-1])

    return sols

candidates = enumerator([out3, out4, out5], [line1, line2, line3], p, 2**64)

for v in candidates:
    key = 0
    for x in v:
        key <<= 64
        key += x
    key = int(key).to_bytes(32, "little")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)

    if b'SECCON' in pt:
        print(pt)
        break

```

**Flag: `SECCON{My_challenges_tend_to_be_solved_by_lattice_'reduction'. How_did_you_do_this_time?}`**
