# verify signature - simple Winternitz One-Time Signature
from typing import List
from src.individual.utils import H
from src.individual import l
import textwrap

def verify_signature(sig: List[bytes], message: str, pk: bytes) -> bool:
    chunk_pks = []
    for i, chunk in enumerate(textwrap.wrap(message, len(message) // l)):
        h = H(chunk.encode('ascii'))
        x = int.from_bytes(h, 'big')

        j = (2 ** 16 - 1) - x

        chunk_pk = H(sig[i], j)
        chunk_pks.append(chunk_pk)

    return pk == H(b''.join(chunk_pks))