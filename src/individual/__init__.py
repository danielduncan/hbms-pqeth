from enum import Enum

# l = 4 is small - probably insecure
l = 4 # message split into l chunks of w bits
# k = 5 gives 2^5 leaves / public keys - adjust depending on l and w
k = 5 # tree depth
# n = 16 so the demo runs quickly - NEVER USE IN PRODUCTION
n = 16 # number of bits secure hash function H outputs

# hash tweaks
class HashTweaks(Enum):
    MESSAGE = 0
    TREE = 1
    CHAIN = 2
