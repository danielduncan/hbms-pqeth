from typing import List, Tuple
from src.individual import HASH_FUNCTION, HashTweaks

# secure hash function H, which can hash n times, and can take a tweak
# defaults to SHA-256, but can be changed to any secure hash function
def H(x: bytes, n: int = 1, tweak: int = HashTweaks.MESSAGE.value, function = HASH_FUNCTION) -> bytes:
    # hash n times
    for _ in range(n):
        # a hash tweak of form H(x + a) makes hashes distinct for identical x
        # tweaks correspond to the application of the hash
        # tweaks are necessary to ensure different but related processes do not collide
        tweaked = x + tweak.to_bytes(1, byteorder='big')
        # hash truncated to 16 bits for demo performance - THIS IS COMPLETELY INSECURE - NEVER USE IN PRODUCTION
        x = function(tweaked).digest()[0:2]
    return x

# secure PRF
def PRF(seed: bytes) -> bytes:
    return H(seed)

# generic Merkle tree with precomputed paths
def merkle_tree(leaves: List[bytes]) -> Tuple[bytes, List[List[bytes]]]:
    assert(len(leaves) > 0 and len(leaves) % 2 == 0)

    tree = [leaves.copy()]

    while len(tree[-1]) > 1:
       level = []
       for i in range(0, len(tree[-1]), 2):
            level.append(H(tree[-1][i] + tree[-1][i + 1]))
       tree.append(level)

    root = tree[-1][0]

    # precompute paths for each leaf
    paths: List[List[bytes]] = []
    for i in range(len(leaves)):
        path: List[bytes] = []
        node = i
        for level in range(len(tree) - 1):
           sibling = node ^ 1 # flip last bit to go left or right...?
           path.append(tree[level][sibling])
           node = node // 2
        paths.append(path)

    return (root, paths)

# find the Merkle root given a leaf (pk) and a path
def merkle_root(pk: bytes, path: List[bytes], index: int) -> bytes:
    node = pk
    for sibling in path:
        if index % 2 == 0:
            node = H(node + sibling)
        else:
            node = H(sibling + node)
        index //= 2

    return node

# split message into l chunks of length w
def get_chunks(message: str, w: int) -> List[str]:
    return [message[i:i + w] for i in range(0, len(message), w)]