from typing import List, Tuple
from src.individual.utils import H, get_chunks
from src import HashTweaks

# standard Winternitz One-Time Signature (WOTS) message signing
def sign_message(sk: List[bytes], message: bytes, w: int) -> List[bytes]:
    sig: List[bytes] = []

    # sign each H(message) chunk of length w
    for i, chunk in enumerate(get_chunks(H(message, tweak=HashTweaks.MESSAGE.value), w)):
        x = int.from_bytes(chunk, 'big') % w
        sig.append(H(sk[i], n=x, tweak=HashTweaks.CHAIN.value))

    return sig

# eXtended Merkle Signature Scheme (XMSS) message signing
def xmss_sign(sk: List[bytes], message: bytes, path: List[bytes], w: int) -> Tuple[List[bytes], List[bytes]]:
    # sign with WOTS
    wots = sign_message(sk, message, w)

    # precomputed path corresponding to the slot will verify the signature
    return (wots, path)
