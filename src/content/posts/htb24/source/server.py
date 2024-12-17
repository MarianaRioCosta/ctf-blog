from hashlib import sha256
from random import uniform
import json

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

from secret import SECRET_MESSAGE
from alice import Alice
from bob import Bob

def json_print(message):
    print(json.dumps(message))

# Python implementation of the Frame-based QKD protocol described here : https://www.mdpi.com/2073-8994/12/6/1053
class QKD:
    def __init__(self, Alice, Bob, pairs = 256, security = 256):
        self.Alice = Alice(pairs)
        self.Bob = Bob(uniform(0, 1))

        self.security = security

    def check_status(self):
        return {"status": "OK", "QBER": self.Bob.depolarizing_probability}

    def execute(self):
        pairs = self.Alice.prepare()
        double_matchings = self.Bob.measure(pairs)

        if not len(double_matchings):
            return {"error": "Key exchange failed, there's no double matchings. Retrying..."}
    
        frames, usable_frames, auxiliary_frames = self.Alice.compute_frames(double_matchings)

        if not len(frames):
            return {"error": "Key exchange failed, there's no frames. Retrying..."}

        bob_sifting_strings = self.Bob.compute_sifting_strings(frames)

        alice_sifting_strings, ambiguous_frames = self.Alice.error_correction(usable_frames, auxiliary_frames, bob_sifting_strings)

        alice_key = self.Alice.generate_shared_key(frames, usable_frames, ambiguous_frames, alice_sifting_strings, bob_sifting_strings)

        bob_key = self.Bob.generate_shared_key(frames, ambiguous_frames, bob_sifting_strings)

        if len(alice_key) < self.security:
            return {"error": "Key exchange failed, the instance does not satisfy the security requirements. Retrying..."}

        if alice_key != bob_key:
            return {"error": "Key exchange failed, both keys are not equal. Retrying..."}

        bob_sifting_strings = list(bob_sifting_strings.values())

        public = {
            "double_matchings": double_matchings,
            "frames": frames,
            "sifting_strings": bob_sifting_strings,
            "ambiguous_frames": ambiguous_frames
        }

        self.shared_key = alice_key.encode()

        return public

    def decrypt_command(self, encrypted_command):
        key = sha256(self.shared_key).digest()

        cipher = AES.new(key, AES.MODE_ECB)
        command = unpad(cipher.decrypt(encrypted_command), 16)
    
        return command.decode()


def main():
    json_print({"info": "To all ships of The Frontier Board, use your secret key to get the coordinates of The Starry Spurr"})
    
    json_print({"info": "Initializing QKD..."})

    while True:
        qkd = QKD(Alice, Bob)
        public = qkd.execute()
        
        json_print(public)

        if "error" not in public:
            status = qkd.check_status()
            json_print(status)
            break

    json_print({"info": "Initialization completed. Only trusted ships can send valid commands"})

    while True:
        try:
            data = json.loads(input("> "))
            encrypted_command = bytes.fromhex(data["command"])
            assert len(encrypted_command) % 16 == 0
        except:
            json_print({"error": "Invalid input. Please, try again"})
            continue

        command = qkd.decrypt_command(encrypted_command)
        
        if command == "OPEN THE GATE":
            FLAG = open('flag.txt').read()
            json_print({"info": f" Welcome to The Frontier Board, the coordinates of The Starry Spurr are {SECRET_MESSAGE}{FLAG}"})
            exit()

        else:
            json_print({"error": "Unknown command. Please, try again"})


if __name__ == '__main__':
    main()