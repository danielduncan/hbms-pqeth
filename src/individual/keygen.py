from os import urandom
from typing import Tuple, List
from src.individual import l, k, n
from src.individual.utils import H, PRF, merkle_tree

# generate secret key sk, by randomly sampling a sequence of bits with any secure PRF
def WOTS_sk(seed: bytes) -> bytes:
    return PRF(seed)

# generate public key pk, by hashing sk (H(sk)) 2^n-1 times, where n is the number of bits a secure hash function H outputs
def WOTS_pk(sk: bytes) -> bytes:
    return H(sk, 2**n - 1)

# standard Winternitz One-Time Signature (WOTS) key generation
def generate_key() -> Tuple[List[bytes], bytes]:
    sks: List[bytes] = []
    pks: List[bytes] = []

    # generate a key pair for each chunk
    for _ in range(l):
        seed: bytes = urandom(32)
        sk: bytes = WOTS_sk(seed)
        pk: bytes = WOTS_pk(sk)
        sks.append(sk)
        pks.append(pk)

    # aggregate public keys into one
    return (sks, H(b''.join(pks)))

# eXtended Merkle Signature Scheme (XMSS) key generation
def xmss_keygen() -> Tuple[List[List[bytes]], bytes, List[List[bytes]]]:
    # slots are single use collections of WOTS secret keys
    slots: List[List[bytes]] = []
    # WOTS public keys form the leaves of a Merkle tree
    leaves: List[bytes] = []
    # tree depth is k, so generate 2^k secret keys (leaves)
    for _ in range(2 ** k):
       sks, pk = generate_key()
       slots.append(sks)
       leaves.append(pk)

    # the root of the Merkle tree is a public key which can be used to verify signatures from any slot (compact, right?)
    # paths are for verification
    root, paths = merkle_tree(leaves)

    return (slots, root, paths)
