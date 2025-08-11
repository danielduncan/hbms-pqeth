from enum import Enum
from hashlib import sha256

HASH_FUNCTION = sha256
n: int = 256 # number of bits secure hash function H outputs
KEY_LIFETIME: int = 10 # lifetime of XMSS keys in epochs TODO: equal to number of leaves i.e. 2^k?

w: int = 128 # chunk size in bits
l: int = n // w # number of chunks in a message
# k = 5 gives 2^5 leaves / public keys - adjust depending on l and w
k: int = 2 # tree depth

# hash tweaks
class HashTweaks(Enum):
    MESSAGE = 0
    TREE = 1
    CHAIN = 2
