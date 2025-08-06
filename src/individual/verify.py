from typing import List
from src.individual.utils import H
from src.individual import l
import textwrap

def verify_signature(sig: List[bytes], message: str, pk: bytes) -> bool:
    w: int = (len(message) // l) * 8 # chunk width in bits
    T: int = 0 # T is a target value used for integrity rather than checksum
    target: int = l * (2 ** w - 1) / 2

    chunk_pks: List[bytes] = []
    for i, chunk in enumerate(textwrap.wrap(message, w)):
        h = H(chunk.encode('ascii'))
        x = int.from_bytes(h, 'big')
        T += x

        j = (2 ** 16 - 1) - x
        chunk_pk = H(sig[i], j)
        chunk_pks.append(chunk_pk)

    print(f"T={T} vs {target}")
    if T != target:
        return False # signature has been modified

    return pk == H(b''.join(chunk_pks))