---
title: "Forgery, UTCTF 2024"
description: "Writeup of Forgery from UTCTF 2024"
date: 2024-04-01
tags: ['Crypto','Rev','EC', 'BLS12-381']
eleventyNavigation:
  key: UTCTF 2024
  parent: Writeups
---


## Overview

Solved this challenge exactly 16 minutes after the ending of the CTF. Me and my team solved this with about 4 sage and C++ scripts that complemented each other.

With this solved, all Crypto was cleared:)

### Description:

```

"This is a forgery." "I have no idea what you are talking about." "DETAIN"

Note: this is both a crypto and rev chall

```

### Source:

We where given the striped and non striped version of the binary + the remote conection.

### SOLUTION

I'd say that finding the attack to do was easy, my struggle was implementing it.

After some (painful) reverse, one can see that the connection is a BLS12-381 signature scheme. We are provided the public key of the server and are expected to send our public key and the signature of the message `Bob and I signed the deal.`, found in the binary.

After some quick googling on attacks on this curve, I figured the attack to do was a [Rogue Key Attack](https://hackmd.io/@benjaminion/bls12-381#Rogue-key-attacks). We chose 3 for our key.

I also found various implementations of the curves, but [this one](https://github.com/AntelopeIO/bls12-381/tree/main) looked like the one used the binary, so my team and I used it.

The **attack** works in the following way:

* Connect to the server and recieve it's public key, $ pk_1$

* Choose a secret value $sk_2$, in this writeup, I use $sk_2 = 3$

* Calculate $pk_2' = sk_2 \cdot g_1 - pk_1$ and send it to the server

* After this, the agregate public key will be $pk_{agg} = pk_1 + pk_2'$

* Hash and sign the message `m = "Bob and I signed the deal."`, obtaining $\gamma = sk_2 \cdot H(m)$, and send it to the server

* Recieve and submit the flag:)

The signature verification will work because:

$$ e(g_1, \gamma) = e(g_1, sk_2 \cdot H(m)) = e(sk_2 g_1, H(m)) = e(pk_1 + pk_2', H(m)) = e(pk_{agg}, H(m)) $$


### Solve Script

Our solve process was the following:

First, we connected to the server, converted the hex public key to a bytearray and inserted it to a C++ script as `input`: 

```cpp

#include <chrono>
#include <bls12-381/bls12-381.hpp>
#include <iostream>
#include <random>

using std::string;
using std::vector;
using std::array;
using std::cout;
using std::endl;

using namespace bls12_381;

template<unsigned long T>
void print_arr(const char* msg, std::array<uint8_t, T> arr) {
    printf("%s = 0x", msg);
    
    for (int i = 0; i < T; i++) {
        printf("%x", arr[i]);
    }
    
    printf("\n");
}

int main(int argc, char * argv[]) {
    uint8_t input[96] = { SERVER's PUBLIC KEY };
    const array<uint64_t, 4> sk{ 0x3, 0x0, 0x0, 0x0 };

    auto pk1 = g1::fromAffineBytesLE(input).value();
    
    print_arr("pk2", pk2.toAffineBytesBE());
    
    return 0;
}

```

This returned the point coordinates to use in this sage script:

```python

from hashlib import sha256

p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
F = GF(p)
a = F(0x00)
b = F(0x04)
E1 = EllipticCurve(F, (a, b))
g1 = E1(0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB, 0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1)
h = 0x396C8C005555E1568C00AAAB0000AAAB
n = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
E1.set_order(n * h)
zeta = GF(n).multiplicative_generator()


x, y = COORDINATES FROM THE C++ SCRIPT

x = x[::-1]
y = y[::-1]

x = int(bytes(x).hex(), 16) 
y = int(bytes(y).hex(), 16) 

pk1 = E1((x,y))


sk2 = 3
pk2 = sk2 * g1 - pk1

m = b'Bob and I signed the deal.'

print(pk2)

```

Lastly, this C++ script signed the message `Bob and I signed the deal.` in `G2`. 
We also used the function `toAffineBytesLE` from this C++ script to serialize the coordinates back again in the curve `G1`, which we submited to the server in hex.

```cpp

#include <chrono>
#include <bls12-381/bls12-381.hpp>
#include <iostream>
#include <random>

using std::string;
using std::vector;
using std::array;
using std::cout;
using std::endl;

using namespace bls12_381;

template<unsigned long T>
void print_arr(std::string msg, std::array<uint8_t, T> arr) {
    printf("%s = [", msg.c_str());
    
    for (int i = 0; i < T; i++) {
        printf("%d, ", arr[i]);
    }
    
    printf("];\n");
}

int main(int argc, char * argv[]) {
    const array<uint64_t, 4> sk{
        0x3,
        0x0,
        0x0,
        0x0
    };
    
    uint8_t lol[] = {66, 111, 98, 32, 97, 110, 100, 32, 73, 32, 115, 105, 103, 110, 101, 100, 32, 116, 104, 101, 32, 100, 101, 97, 108, 46};
    std::span<const uint8_t> msg{ lol };
    
    auto point = sign(sk, msg);
    
    print_arr(std::string("point_g2"), point.toAffineBytesLE());
}

```

**Flag: `utflag{glory_to_arstotzka_and_cryptorev}`**