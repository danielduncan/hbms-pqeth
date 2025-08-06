# verify signature - simple Winternitz One-Time Signature
from src.individual.utils import H

def verify_signature(sig, message, pk):
    h = H(message.encode('ascii'))
    x = int.from_bytes(h, 'big')

    j = (2 ** 16 - 1) - x

    validity = (pk == H(sig, j))

    return validity