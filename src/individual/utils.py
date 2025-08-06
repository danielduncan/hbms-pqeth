import hashlib
from importlib.resources import path
from typing import List, Tuple

def H(x: bytes, n: int = 1) -> bytes:
    # hash n times
    for _ in range(n):
        # hash truncated to 16 bits for demo performance - THIS IS COMPLETELY INSECURE - NEVER USE IN PRODUCTION
        x = hashlib.sha256(x).digest()[0:2]
    return x

def PRF(seed) -> bytes:
    return H(seed)

def merkle_tree(leaves: List[bytes]) -> Tuple[bytes, List[List[bytes]]]:
    assert(len(leaves) > 0 and len(leaves) % 2 == 0)

    tree = [leaves.copy()]

    while len(tree[-1]) > 1:
       level = []
       for i in range(0, len(tree[-1]), 2):
            level.append(H(tree[-1][i] + tree[-1][i + 1]))
       tree.append(level)

    root = tree[-1][0]

    paths = []
    for i in range(len(leaves)):
        path = []
        node = i
        for level in range(len(tree) - 1):
           sibling = node ^ 1 # flip last bit to go left or right...?
           path.append(tree[level][sibling])
           node = node // 2
        paths.append(path)

    return (root, paths)

# double check this function
def merkle_root(pk: bytes, path: List[bytes], index: int) -> bytes:
    node = pk
    for sibling in path:
        if index % 2 == 0:
            node = H(node + sibling)
        else:
            node = H(sibling + node)
        index //= 2

    return node
