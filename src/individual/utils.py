import hashlib

def H(x):
    return hashlib.sha256(x).digest()
