import pytest
import math
import random
import string
from src.aggregation.aggregate import aggregate_signatures
from src import n, k, l, HashTweaks, KEY_LIFETIME
from src.individual.keygen import generate_key, xmss_keygen
from src.individual.sign import sign_message, xmss_sign
from src.individual.utils import H, PRF, merkle_tree, merkle_root, get_chunks
from src.individual.verify import verify_signature, xmss_verify

epoch = random.randint(0, KEY_LIFETIME)
message_length = 4 * l # length of message must be divisible by l for sign_message to work
message = ''.join(random.choices(string.ascii_letters + string.digits, k = message_length))
index = random.randint(0, 2 ** k) # random index for slots
keylen = 32 # expected key length

def test_generate_key():
    # generate_key
    sks, pk = generate_key()
    assert pk is not None
    assert sks is not None
    assert isinstance(pk, bytes)
    assert len(pk) == keylen
    for sk in sks:
        assert isinstance(sk, bytes)
        assert len(sk) == keylen

def test_xmss_keygen():
    # xmss_keygen
    slots, root, paths = xmss_keygen(epoch)

    for sks in slots:
        for sk in sks:
            assert isinstance(sk, bytes)
            assert len(sk) == keylen

def test_sign_message():
    # setup
    sks, pk = generate_key()

    # sign_message
    signatures = sign_message(sks, message)
    for sig in signatures:
        assert isinstance(sig, bytes)
    str_sig = ''.join(b.decode('latin1') for b in signatures)
    assert str_sig != message

def test_xmss_sign():
    # setup
    slots, root, paths = xmss_keygen(epoch)

    # xmss_sign
    _, wots, path = xmss_sign(slots, index, message, paths)
    for sig in wots:
        assert isinstance(sig, bytes)
    str_sig = ''.join(b.decode('latin1') for b in wots)
    assert str_sig != message
    assert path == paths[index]

def test_merkle_tree():
    # setup
    leaves = [b'a', b'b', b'c', b'd']
    H1 = H(b'a' + b'b', tweak=HashTweaks.TREE.value)
    H2 = H(b'c' + b'd', tweak=HashTweaks.TREE.value)
    expected_root = H(H1 + H2, tweak=HashTweaks.TREE.value)
    expected_paths = [[b'b', H2], [b'a', H2], [b'd', H1], [b'c', H1]]

    # merkle_tree
    root, paths = merkle_tree(leaves)
    assert root == expected_root
    assert paths == expected_paths

def test_merkle_root():
    # setup
    leaves = [b'a', b'b', b'c', b'd']
    root, paths = merkle_tree(leaves)

    for index, leaf in enumerate(leaves):
        expected_root = merkle_root(leaf, paths[index], index)
        assert expected_root == root

def test_get_chunks():
    # setup
    byte_a = bytes([0b01101100])
    byte_b = bytes([0b10100110])
    data = byte_a + byte_b

    chunks = get_chunks(data, 8) # minimum value for w is 8
    assert len(chunks) == 2
    assert chunks[0] == byte_a
    assert chunks[1] == byte_b

    chunks = get_chunks(data, 16)
    assert len(chunks) == 1
    assert chunks == [data]

def test_verify_signature():
    # setup
    sks, pk = generate_key()
    signature = sign_message(sks, message)

    # verify_signature
    assert verify_signature(signature, message, pk)

def test_xmss_verify():
    # setup
    slots, root, paths = xmss_keygen(epoch)
    sig = xmss_sign(slots, index, message, paths)

    # xmss_verify
    assert xmss_verify(sig, message, root)