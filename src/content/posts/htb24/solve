from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from hashlib import sha256
from bob import Bob
from pwn import *
from z3 import *
import json

r = remote('ip.ip.ip.ip', 'port') # Fill-in your IP and port for your box

def init():
    a = b'info'
    while b'info' in a:
        a = r.recvline()
    data = json.loads(a)

    double_matchings = data["double_matchings"]
    frames = data["frames"]
    frames = [(x[0],x[1]) for x in frames] # We want list of tuples for consistency
    bob_sifting_strings = data["sifting_strings"]
    ambiguous_frames = data["ambiguous_frames"]          
    ambiguous_frames = [(x[0],x[1]) for x in ambiguous_frames]
    return double_matchings, frames, bob_sifting_strings, ambiguous_frames

def enc(shared_key):
    key = sha256(shared_key).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    command = cipher.encrypt(pad(b"OPEN THE GATE",16))
    return command.hex()

def flag(shared_key):
    cmd = enc(shared_key.encode())
    r.sendline(b'{"command":"'+cmd.encode()+b'"}')
    return r.clean(timeout=3)

double_matchings, frames, sifting_bits, ambiguous_frames = init()

# We can recover the keys from bob_sifting_strings, as Python usually perserves the order of keys in dicts
bob_sifting_strings = {}
for i, frame in enumerate(frames):
    bob_sifting_strings[frame] = sifting_bits[i]

# ------------------------------------------------------------------------------------------------

s = Solver()
crafted_basis = {}

for i in range(256):
    crafted_basis[i] = BitVec('bob_{}_basis'.format(i), 1)

for i, frame in enumerate(frames):
    # Exploit compute_sifting_strings function from bob.py
    basis, mr = bob_sifting_strings[frame].split(',')
    basis = list(map(int, basis))
    mr = list(map(int, mr))
    i,j = frame

    x_s = BitVecVal(0,1)
    x_s = If(crafted_basis[i] == 1, x_s ^ BitVecVal(mr[0], x_s.size()), x_s)
    x_s = If(crafted_basis[j] == 1, x_s ^ BitVecVal(mr[1], x_s.size()), x_s)

    z_s = BitVecVal(0,1)
    z_s = If(crafted_basis[i] == 0, z_s ^ BitVecVal(mr[0], z_s.size()), z_s)
    z_s = If(crafted_basis[j] == 0, z_s ^ BitVecVal(mr[1], z_s.size()), z_s)

    s.add(x_s == basis[0])
    s.add(z_s == basis[1])

assert s.check() == sat
m = s.model()
bob = Bob(1)

for i in crafted_basis:
    if m[crafted_basis[i]] == 1:
        bob.measurement_basis[i] = 'X'
    elif m[crafted_basis[i]] == 0:
        bob.measurement_basis[i] = 'Z'

crafted_key = bob.generate_shared_key(frames, ambiguous_frames, bob_sifting_strings)
print(flag(crafted_key))