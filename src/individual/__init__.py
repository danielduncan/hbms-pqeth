from enum import Enum
from hashlib import sha256
from blake3 import blake3

HASH_FUNCTION = blake3
# n = 16 so the demo runs quickly - NEVER USE IN PRODUCTION
n: int = 16 # number of bits secure hash function H outputs
# NOTE: keygen behaves O(1000^HASH_LENGTH) time (this is very bad)
HASH_LENGTH: int = n // 8 # hash length in bytes
KEY_LIFETIME: int = 10 # lifetime of XMSS keys in epochs TODO: equal to number of leaves i.e. 2^k?

# NOTE: keygen behaves O(lk) time
# l = 4 is small - probably insecure
l: int = 4 # message split into l chunks of w bits
# k = 5 gives 2^5 leaves / public keys - adjust depending on l and w
k: int = 5 # tree depth

# hash tweaks
class HashTweaks(Enum):
    MESSAGE = 0
    TREE = 1
    CHAIN = 2
