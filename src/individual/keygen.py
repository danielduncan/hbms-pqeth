# TODO: key generation
from os import urandom
from src.individual.utils import H

def generate_key(r, birthday, lifetime):
    seed = urandom(32)
    # expand using SHA-256 as a PRF
    sk = H(seed)

    # hash chain
    for _ in range(r):
        sk = H(sk)

    # pk
    pk = H(sk) # TODO: placeholder!

    return (sk, pk)
