from secrets import randbits

from qiskit import transpile
from qiskit_aer import Aer
from qiskit_aer.noise.errors import pauli_error, depolarizing_error
from qiskit_aer.noise import NoiseModel

from helpers import BOB_MR_DERIVATION, KEY_DERIVATION

# Receiver class
class Bob:
    def __init__(self, depolarizing_probability = 0):
        self.depolarizing_probability = depolarizing_probability
        
        self.measurement_basis = {}
        self.measurement_results = {}
        self.backend = Aer.get_backend("qasm_simulator")

    def noise_model(self, p):
        error_model = depolarizing_error(p, 1)
        
        noise_model = NoiseModel()
        noise_model.add_all_qubit_quantum_error(error_model, "measure")

        return noise_model
        
    def measure(self, pairs):
        double_matchings = []

        noise_model = None
        if self.depolarizing_probability > 0:
            noise_model = self.noise_model(self.depolarizing_probability)
        
        for i in range(len(pairs)):
            basis = randbits(1)
            if basis:
                # Measurement in "X" basis
                pairs[i][0].h(0)
                pairs[i][1].h(0)
                
            pairs[i][0].measure(0, 0)
            pairs[i][1].measure(0, 0)

            bits = ""
            for circuit in pairs[i]:
                transpiled = transpile(circuit, self.backend)
                results = self.backend.run(transpiled, noise_model = noise_model, shots = 1).result().get_counts()
                bits += list(results.keys())[0]
            
            if bits[0] == bits[1]: double_matchings.append(i)
            
            self.measurement_results[i] = bits
            self.measurement_basis[i] = "X" if basis else "Z"
        
        return double_matchings
    
    def compute_sifting_bits(self, frame):
        sifting_bits = {
            "X": 0, 
            "Z": 0
        }
        
        for pair in frame:
            sifting_bits[self.measurement_basis[pair]] ^= int(self.measurement_results[pair][0])
            
        return ''.join(map(str, sifting_bits.values()))

    def compute_measured_bits(self, frame):
        measured_bits = []

        for pair in frame:
            measured_bits.append(self.measurement_results[pair][0]) # since both bits are equal due to the double matching event

        return ''.join(measured_bits)
            
    def compute_sifting_strings(self, frames):
        sifting_strings = {}

        for frame in frames:
            sifting_bits = self.compute_sifting_bits(frame)
            measured_bits = self.compute_measured_bits(frame)

            sifting_strings[frame] = f"{sifting_bits},{measured_bits}"

        return sifting_strings
    
    def generate_shared_key(self, frames, ambiguous_frames, sifting_strings):
        shared_secret = ""

        for frame in frames:
            if frame in ambiguous_frames:
                continue

            else:
                basis_orientation = (self.measurement_basis[frame[0]], self.measurement_basis[frame[1]])
                measurement_result = BOB_MR_DERIVATION[basis_orientation]
                shared_secret += KEY_DERIVATION[sifting_strings[frame]][measurement_result]

        return shared_secret
            
            