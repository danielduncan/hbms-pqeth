# verify signature - simple Winternitz One-Time Signature
from typing import List, Tuple
from src.individual.utils import H, merkle_root
from src.individual import l
import textwrap

def verify_wots(sig: List[bytes], message: str) -> bytes:
    chunk_pks = []
    for i, chunk in enumerate(textwrap.wrap(message, len(message) // l)):
        h = H(chunk.encode('ascii'))
        x = int.from_bytes(h, 'big')

        j = (2 ** 16 - 1) - x

        chunk_pk = H(sig[i], j)
        chunk_pks.append(chunk_pk)
    
    return H(b''.join(chunk_pks))

def verify_signature(sig: List[bytes], message: str, pk: bytes) -> bool:
    return pk == verify_wots(sig, message)

# sig <- (index, wots, path)
def xmss_verify(sig: Tuple[int, List[bytes], List[bytes]], message: str, pk: bytes) -> bool:
    index, wots_sig, path = sig
    
    leaf = verify_wots(wots_sig, message)
    computed_root = merkle_root(leaf, path, index)
    
    return computed_root == pk
