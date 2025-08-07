import pytest
import math
import random
import string
from src.aggregation.aggregate import aggregate_signatures
from src.individual import n, k, l
from src.individual.keygen import generate_key, xmss_keygen
from src.individual.sign import sign_message, xmss_sign
from src.individual.utils import H, PRF, merkle_tree, merkle_tree, get_chunks
from src.individual.verify import verify_signature

message_length = 4 * l # length of message must be divisible by l for sign_message to work
message = ''.join(random.choices(string.ascii_letters + string.digits, k = message_length))

def test_generate_key():
    # generate_key
    sks, pk = generate_key()
    assert pk is not None
    assert sks is not None
    assert isinstance(pk, bytes)
    assert len(pk) == 2
    for sk in sks:
        assert isinstance(sk, bytes)
        assert len(sk) == 2

def test_sign_message():
    # setup
    sks, pk = generate_key()

    # sign_message
    signatures = sign_message(sks, message)
    for sig in signatures:
        assert isinstance(sig, bytes)
    str_sig = ''.join(b.decode('latin1') for b in signatures)
    assert str_sig != message

def test_get_chunks():
    str_a = '01101100'
    str_b = '10100110'
    data = str_a + str_b

    expected_chunks = ['01', '10', '11', '00', '10', '10', '01', '10']

    chunks = get_chunks(data, 2)
    print(chunks)
    assert len(chunks) == 8
    assert chunks == expected_chunks

    chunks = get_chunks(data, 8)
    assert len(chunks) == 2
    assert chunks[0] == str_a
    assert chunks[1] == str_b

def test_verify_signature():
    # setup
    sks, pk = generate_key()
    signature = sign_message(sks, message)

    # verify_signature
    assert verify_signature(signature, message, pk)