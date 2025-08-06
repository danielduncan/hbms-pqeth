# verify signature - simple Winternitz One-Time Signature
from typing import List
from src.individual.utils import H
from src.individual import l
import textwrap

def verify_signature(sig: List[bytes], message: str, pk: List[bytes]) -> bool:
    valid = []
    for i, chunk in enumerate(textwrap.wrap(message, len(message) // l)):
        h = H(chunk.encode('ascii'))
        x = int.from_bytes(h, 'big')

        j = (2 ** 16 - 1) - x

        valid.append((pk[i] == H(sig[i], j)))

    return all(valid)