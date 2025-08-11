from typing import Callable
from src.individual.keygen import xmss_keygen
from src.individual.sign import xmss_sign
from src.individual.verify import xmss_verify
from src.aggregation.aggregate import aggregate_signatures, aggregate_verify
from src.aggregation.harness import NoirHarness

"""
Hash-Based Multi-Signature (HBMS) scheme
Initialised once for the application, universal for all validators
"""
class HBMS:
    def __init__(self, H: Callable, n: int, N: int, w: int, k: int):
        self.H = H # hash function
        self.LEN = n # hash/message length
        self.N = N # number of validators
        self.W = w # chunk length
        assert(n % w == 0) # ensure chunks will be of equal length
        self.L = n // w # number of sigs
        self.K = k # Merkle tree depth
        self.SNARK_HARNESS = NoirHarness(self.LEN, self.N, self.W, self.L, self.K) # SNARK harness for aggregation

        self.keygen = xmss_keygen
        self.sign = xmss_sign
        self.verify = xmss_verify
        self.aggregate_signatures = aggregate_signatures
        self.aggregate_verify = aggregate_verify

"""
Scheme for each validator
Initialised and unique for each validator
"""
class Scheme:
    def __init__(self, scheme: HBMS):
        self.scheme = scheme
        self.pk = []
        self.sks = []

    def keygen(self, epoch):
        keys = self.scheme.keygen(self.scheme.W, self.scheme.K, self.scheme.L)
        self.birthepoch = epoch
        self.sks = keys[0]
        self.pk = keys[1]
        self.paths = keys[2]

        return (self.sks, self.pk, self.paths)

    def sign(self, message, epoch):
        slot = epoch - self.birthepoch

        # if out of slots, regenerate keys
        if slot < 0 or slot >= len(self.sks):
            self.keygen(epoch)
            self.sign(message, epoch)

        sk = self.sks[slot]
        path = self.paths[slot]

        wots, path = self.scheme.sign(sk, message, path, self.scheme.W)
        return (slot, wots, path)

    def verify(self, sig, message, pk):
        return self.scheme.verify(sig, message, pk, self.scheme.W)

    def aggregate_signatures(self, message, signatures):
        return self.scheme.aggregate_signatures(self.scheme.SNARK_HARNESS, message, signatures)

    def aggregate_verify(self):
        return self.scheme.aggregate_verify(self.scheme.SNARK_HARNESS)
