from typing import List, Tuple
from src.individual.utils import H, get_chunks, merkle_root
from src.individual import HashTweaks, w

# standard Winternitz One-Time Signature (WOTS) signature verification
def verify_wots(sig: List[bytes], message: str) -> bytes:
    # each chunk has a pk
    pks: List[bytes] = []

<<<<<<< HEAD
    for i, chunk in enumerate(get_chunks(message, w)):
        h = H(chunk.encode('ascii'), tweak=HashTweaks.MESSAGE.value)
        x = int.from_bytes(h, 'big')
        T += x
=======
    for i, chunk in enumerate(get_chunks(H(message.encode('ascii'), tweak=HashTweaks.MESSAGE.value), w)):
        x = int.from_bytes(chunk, 'big') % w
>>>>>>> main

        # number of times required to hash the signature to get the original pk
        j = w - x

        chunk_pk = H(sig[i], n=j, tweak=HashTweaks.CHAIN.value)
        pks.append(chunk_pk)
    
    # aggregate pks into one that should match the signers public key
    return H(b''.join(pks), tweak=HashTweaks.CHAIN.value)

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

# eXtended Merkle Signature Scheme (XMSS) signature verification
def xmss_verify(sig: Tuple[int, List[bytes], List[bytes]], message: str, pk: bytes) -> bool:
    index, wots, path = sig
    
    # compute leaf (pk) associated with given WOTS signature
    leaf = verify_wots(wots, message)
    # compute Merkle root associated with given pk and path
    root = merkle_root(leaf, path, index)
    
    # if the Merkle root from public key and path matches the public key given WOTS, signature is valid 
    return root == pk
