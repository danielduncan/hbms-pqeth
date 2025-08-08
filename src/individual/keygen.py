from os import urandom
from typing import Tuple, List
from src.individual import HashTweaks, l, k, w, KEY_LIFETIME
from src.individual.utils import H, PRF, merkle_tree
from concurrent.futures import ThreadPoolExecutor

# generate secret key sk, by randomly sampling a sequence of bits with any secure PRF
def WOTS_sk(seed: bytes) -> bytes:
    return PRF(seed)

# generate public key pk, by hashing sk w times (H^w(sk))
def WOTS_pk(sk: bytes) -> bytes:
    return H(sk, n=w, tweak=HashTweaks.CHAIN.value)

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
    return (sks, H(b''.join(pks), tweak=HashTweaks.CHAIN.value))

# TODO: SEQUENTIAL SLOTS - USE SYNCHRONISED WITH TIME
# TODO: E.G. SLOT 0 IS USED AT EPOCH 0, SLOT 1 AT EPOCH 1, ETC.
# TODO: REGENERATE TREE ONCE EXHAUSTED - I.E. ONCE INITIAL EPOCH + LIFETIME REACHED
# TODO: BALANCE TREE SIZE AND REFRESH FREQUENCY
# eXtended Merkle Signature Scheme (XMSS) key generation
def xmss_keygen(epoch: int, lifetime: int = KEY_LIFETIME) -> Tuple[List[List[bytes]], bytes, List[List[bytes]]]:
    # slots are single use collections of WOTS secret keys
    slots: List[List[bytes]] = []
    # WOTS public keys form the leaves of a Merkle tree
    leaves: List[bytes] = []
    # parallelise
    with ThreadPoolExecutor() as executor:
        # tree depth is k, so generate 2^k secret keys (leaves)
        results = list(executor.map(lambda _: generate_key(), range(2 ** k)))
    for sks, pk in results:
       slots.append(sks)
       leaves.append(pk)

    # the root of the Merkle tree is a public key which can be used to verify signatures from any slot (compact, right?)
    # paths are for verification
    root, paths = merkle_tree(leaves)

    return (slots, root, paths)
