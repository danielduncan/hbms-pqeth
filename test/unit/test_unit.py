import pytest
import math
from src.aggregation.aggregate import aggregate_signatures
from src.individual.keygen import generate_key
from src.individual.sign import sign_message
from src.individual.verify import verify_signature

n = 32 # security parameter in bytes
h = 10 # height of Merkle tree
w = 16 # Winternitz parameter
l_1 = math.ceil((8 * n) / math.log2(w))
l_2 = math.ceil(math.log2(l_1 * (w - 1)) / math.log2(w))
l = l_1 + l_2 # Total number of chains

def test_generate_key():
    # generate_key
    pk, sk = generate_key()
    assert pk is not None
    assert sk is not None
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    assert len(pk) == (2 * (h + l.bit_length()) + 1) * n
    assert len(sk) <= 2*n

def test_sign_message():
    # setup
    message = b'Example message'
    pk, sk = generate_key()

    # sign_message
    signature = sign_message(sk, message)
    assert isinstance(signature, bytes)
    assert signature != message

def test_verify_signature():
    # setup
    message = b'Another example message'
    pk, sk = generate_key()
    signature = sign_message(sk, message)

    # verify_signature
    assert verify_signature(signature, message)