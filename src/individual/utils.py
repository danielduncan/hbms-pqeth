import hashlib
from typing import List

def H(x: bytes, n: int = 1) -> bytes:
    # hash n times
    for _ in range(n):
        # hash truncated to 16 bits for demo performance - THIS IS COMPLETELY INSECURE - NEVER USE IN PRODUCTION
        x = hashlib.sha256(x).digest()[0:2]
    return x

def PRF(seed) -> bytes:
    return H(seed)
