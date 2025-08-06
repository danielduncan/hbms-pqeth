from typing import List, Tuple
from src.individual.utils import H
from src.individual import l
import textwrap

# Message signing with parallelisable Winternitz One-Time Signature
def sign_message(sk: List[bytes], message: str) -> List[bytes]:
    sig = []
    for i, chunk in enumerate(textwrap.wrap(message, len(message) // l)):
        h = H(chunk.encode('ascii'))
        x = int.from_bytes(h, 'big')
        sig.append(H(sk[i], x))

    return sig

def xmss_sign(slots: List[List[bytes]], index: int, message: str, paths: List[List[bytes]]) -> Tuple[int, List[bytes], List[bytes]]:
    sk = slots[index]
    path = paths[index]

    wots = sign_message(sk, message)

    return (index, wots, path)
