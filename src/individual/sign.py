from typing import List, Tuple
from src.individual.utils import H, get_chunks
from src import HashTweaks, w

# standard Winternitz One-Time Signature (WOTS) message signing
def sign_message(sk: List[bytes], message: str) -> List[bytes]:
    sig: List[bytes] = []

    # sign each H(message) chunk of length w
    for i, chunk in enumerate(get_chunks(H(message.encode('ascii'), tweak=HashTweaks.MESSAGE.value), w)):
        x = int.from_bytes(chunk, 'big') % w
        sig.append(H(sk[i], n=x, tweak=HashTweaks.CHAIN.value))

    return sig

# eXtended Merkle Signature Scheme (XMSS) message signing
def xmss_sign(slots: List[List[bytes]], index: int, message: str, paths: List[List[bytes]]) -> Tuple[int, List[bytes], List[bytes]]:
    # index dictates which slot is used
    sk = slots[index]
    # precomputed path corresponding to the slot index will verify the signature
    path = paths[index]

    # sign with WOTS
    wots = sign_message(sk, message)

    return (index, wots, path)
