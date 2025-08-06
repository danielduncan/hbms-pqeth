# TODO: message signing - simple Winternitz One-Time Signature
from src.individual.utils import H

# w = 16 # message split into chunks of w bits

def sign_message(sk, message):
    h = H(message.encode('ascii'))
    x = int.from_bytes(h, 'big')
    sig = H(sk, x)

    return sig
