from typing import List, Tuple
from src.individual.utils import H, get_chunks, merkle_root
from src.individual import HashTweaks, l, n

# standard Winternitz One-Time Signature (WOTS) signature verification
def verify_wots(sig: List[bytes], message: str) -> bytes:
    w: int = len(message) // l
    # each chunk has a pk
    pks: List[bytes] = []

    for i, chunk in enumerate(get_chunks(message, w)):
        h = H(chunk.encode('ascii'), tweak=HashTweaks.MESSAGE.value)
        x = int.from_bytes(h, 'big')

        # number of times required to hash the signature to get the original pk
        j = (2 ** n - 1) - x

        chunk_pk = H(sig[i], j, tweak=HashTweaks.CHAIN.value)
        pks.append(chunk_pk)
    
    # aggregate pks into one that should match the signers public key
    return H(b''.join(pks), tweak=HashTweaks.CHAIN.value)

def verify_signature(sig: List[bytes], message: str, pk: bytes) -> bool:
    return pk == verify_wots(sig, message)

# eXtended Merkle Signature Scheme (XMSS) signature verification
def xmss_verify(sig: Tuple[int, List[bytes], List[bytes]], message: str, pk: bytes) -> bool:
    index, wots, path = sig
    
    # compute leaf (pk) associated with given WOTS signature
    leaf = verify_wots(wots, message)
    # compute Merkle root associated with given pk and path
    root = merkle_root(leaf, path, index)
    
    # if the Merkle root from public key and path matches the public key given WOTS, signature is valid 
    return root == pk
