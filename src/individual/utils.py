from typing import List, Tuple
from src import HashTweaks
from hashlib import sha256

# secure hash function H, which can hash n times, and can take a tweak
# defaults to SHA-256, but can be changed to any secure hash function
def H(x: bytes, n: int = 1, tweak: int = -1, function = sha256) -> bytes:
    # hash n times
    for _ in range(n):
        # a hash tweak of form H(x + a) makes hashes distinct for identical x
        # tweaks correspond to the application of the hash
        # tweaks are necessary to ensure different but related processes do not collide
        if tweak != -1:
            tweaked = x + tweak.to_bytes(1, byteorder='big')
        else:
            tweaked = x
        x = function(tweaked).digest()

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
            level.append(H(tree[-1][i] + tree[-1][i + 1], tweak=HashTweaks.TREE.value))
       tree.append(level)

    root = tree[-1][0]

    # precompute paths for each leaf
    paths: List[List[bytes]] = []
    for i in range(len(leaves)):
        path: List[bytes] = []
        node = i
        for level in range(len(tree) - 1):
           sibling = node ^ 1
           path.append(tree[level][sibling])
           node = node // 2
        paths.append(path)

    return (root, paths)

# find the Merkle root given a leaf (pk) and a path
def merkle_root(pk: bytes, path: List[bytes], index: int) -> bytes:
    node = pk
    for sibling in path:
        if index % 2 == 0:
            node = H(node + sibling, tweak=HashTweaks.TREE.value)
        else:
            node = H(sibling + node, tweak=HashTweaks.TREE.value)
        index //= 2

    return node

# split message into l chunks of length w
def get_chunks(message: bytes, w: int) -> List[bytes]:
    return [message[i:i + w // 8] for i in range(0, len(message), w // 8)]