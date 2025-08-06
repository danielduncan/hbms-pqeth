from os import urandom
from typing import Tuple, List
from src.individual import l
from src.individual.utils import H, PRF

# generate secret key sk by randomly sampling a sequence of bits
def WOTS_sk(seed: bytes) -> bytes:
    return PRF(seed)

# generate public key pk by applying H 2^n - 1 times to sk, where n is number of bits H outputs
def WOTS_pk(sk: bytes) -> bytes:
    # n = 16 for demo performance - NEVER USE IN PRODUCTION
    return H(sk, 2**16 - 1)

# Parallelisable Winternitz One-Time Signature
def generate_key() -> Tuple[List[bytes], bytes]:
    sks = []
    pks = []

    # generate a key pair for each chunk
    for _ in range(l):
        seed = urandom(32)
        sk = WOTS_sk(seed)
        pk = WOTS_pk(sk)
        sks.append(sk)
        pks.append(pk)

    # aggregate public keys into one
    return (sks, H(b''.join(pks)))
