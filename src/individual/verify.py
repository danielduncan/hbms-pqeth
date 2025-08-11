from typing import List, Tuple
from src.individual.utils import H, get_chunks, merkle_root
from src import HashTweaks

# standard Winternitz One-Time Signature (WOTS) signature verification
def verify_wots(sig: List[bytes], message: bytes, w: int) -> bytes:
    # each chunk has a pk
    pks: List[bytes] = []

    for i, chunk in enumerate(get_chunks(H(message, tweak=HashTweaks.MESSAGE.value), w)):
        x = int.from_bytes(chunk, 'big') % w

        # number of times required to hash the signature to get the original pk
        j = w - x

        chunk_pk = H(sig[i], n=j, tweak=HashTweaks.CHAIN.value)
        pks.append(chunk_pk)
    
    # aggregate pks into one that should match the signers public key
    return H(b''.join(pks), tweak=HashTweaks.CHAIN.value)

def verify_signature(sig: List[bytes], message: bytes, pk: bytes, w: int) -> bool:
    return pk == verify_wots(sig, message, w)

# eXtended Merkle Signature Scheme (XMSS) signature verification
def xmss_verify(sig: Tuple[bytes, Tuple[int, List[bytes], List[bytes]]], message: bytes, pk: bytes, w: int) -> bool:
    _, (index, wots, path) = sig
    
    # compute leaf (pk) associated with given WOTS signature
    leaf = verify_wots(wots, message, w)
    # compute Merkle root associated with given pk and path
    root = merkle_root(leaf, path, index)
    
    # if the Merkle root from public key and path matches the public key given WOTS, signature is valid 
    return root == pk
