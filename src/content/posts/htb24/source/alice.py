from itertools import combinations
from secrets import randbits
from random import shuffle

from qiskit import QuantumCircuit

from helpers import USABLE_FRAMES, VALID_SS, AUXILIARY_FRAMES, ALICE_MR_DERIVATION, ERROR_CORRECTION_RULES, KEY_DERIVATION

# Transmitter class
class Alice:
    def __init__(self, pairs):
        self.pairs = pairs
        self.pairs_data = {}
        
        # Setting up global parameters. Local variables with the same name refers to the frames generated in the actual QKD instance
        self.usable_frames = USABLE_FRAMES
        self.usable_frames_iterable = list(self.usable_frames.keys())

        self.auxiliary_frames = AUXILIARY_FRAMES
        self.auxiliary_frames_iterable = list(self.auxiliary_frames.keys())
        
        self.generate_pairs()
        
    def generate_pairs(self):
        for i in range(self.pairs):
            x, z = [ randbits(1) for _ in range(2) ]
            self.pairs_data[i] = f"{x}x,{z}z"

    def prepare(self):
        pairs = []
        for i in range(self.pairs):
            circuits = self.generate_circuits(self.pairs_data[i])
            pairs.append(circuits)
        return pairs
            
    def generate_circuits(self, pair):
        x, z = [ int(state[0]) for state in pair.split(",") ]
        circuits = [ QuantumCircuit(1, 1) for _ in range(2) ]
        
        if x: circuits[0].x(0)
        if z: circuits[1].x(0)
        
        circuits[0].h(0)
        
        return circuits
    
    def public_frame_to_private_frame(self, frame):
        return (self.pairs_data[frame[0]], self.pairs_data[frame[1]])

    def compute_frames(self, double_matchings):
        usable_frames = {}
        auxiliary_frames = {}
        
        public_frames = list(combinations(double_matchings, 2))

        for public_frame in public_frames:
            private_frame = self.public_frame_to_private_frame(public_frame)

            if private_frame in self.usable_frames_iterable:
                usable_frames[public_frame] = self.usable_frames[private_frame]
            
            elif private_frame in self.auxiliary_frames_iterable:
                auxiliary_frames[public_frame] = self.auxiliary_frames[private_frame]

        frames = list(usable_frames.keys()) + list(auxiliary_frames.keys())
        
        shuffle(frames)

        return frames, usable_frames, auxiliary_frames

    def verify_undetected_error(self, pair, detection_frame, required_sifting_string, frame, auxiliary_frames, auxiliary_frames_iterable, sifting_string):
        for auxiliary_frame in auxiliary_frames_iterable:
            if  (
                    frame[pair]                       == auxiliary_frame[0]      and 
                    auxiliary_frames[auxiliary_frame] == detection_frame         and 
                    sifting_string[auxiliary_frame]   == required_sifting_string
                ):

                return True

        return False
    
    def error_correction(self, usable_frames, auxiliary_frames, bob_sifting_strings):
        alice_sifting_strings = bob_sifting_strings.copy()
        
        ambiguous_frames = []

        usable_frames_iterable = list(usable_frames.keys())
        auxiliary_frames_iterable = list(auxiliary_frames.keys())

        for frame in usable_frames_iterable:
            if alice_sifting_strings[frame] in VALID_SS[usable_frames[frame]]:
                sifting_bits = alice_sifting_strings[frame][:2]

                if sifting_bits == "01" or sifting_bits == "10":
                    ambiguous_frames.append(frame)

                else:
                    pair, detection_frame, required_sifting_string, corrections = ERROR_CORRECTION_RULES[usable_frames[frame]]
                    
                    verify = self.verify_undetected_error(
                                pair, 
                                detection_frame, 
                                required_sifting_string, 
                                frame, 
                                auxiliary_frames,
                                auxiliary_frames_iterable, 
                                alice_sifting_strings
                            )

                    if verify:
                        if  alice_sifting_strings[frame] == "00,11":
                            alice_sifting_strings[frame] = corrections[0]
                            
                        elif alice_sifting_strings[frame] == "11,11":
                             alice_sifting_strings[frame] = corrections[1]

            else:
                ambiguous_frames.append(frame)

        ambiguous_frames += auxiliary_frames

        shuffle(ambiguous_frames)
        
        return alice_sifting_strings, ambiguous_frames

    def generate_shared_key(self, frames, usable_frames, ambiguous_frames, alice_sifting_strings, bob_sifting_strings):
        shared_secret = ""

        for frame in frames:
            if frame in ambiguous_frames:
                continue

            else:
                sifting_bits = alice_sifting_strings[frame][:2]
                measurement_result = ALICE_MR_DERIVATION[usable_frames[frame]][sifting_bits]
                shared_secret += KEY_DERIVATION[bob_sifting_strings[frame]][measurement_result]
        
        return shared_secret