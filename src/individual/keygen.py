from os import urandom
from typing import Tuple
from src.individual.utils import H, PRF

# generate secret key sk by randomly sampling a sequence of bits
def WOTS_sk(seed: bytes) -> bytes:
    return PRF(seed)

# generate public key pk by applying H 2^n - 1 times to sk, where n is number of bits H outputs
def WOTS_pk(sk: bytes) -> bytes:
    # n = 16 for demo performance - NEVER USE IN PRODUCTION
    return H(sk, 2**16 - 1)

# Simple Winternitz One-Time Signature
def generate_key() -> Tuple[bytes, bytes]:
    seed = urandom(32)

    return (WOTS_sk(seed), WOTS_pk(WOTS_sk(seed)))
