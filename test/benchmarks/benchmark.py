import time
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from src.scheme import HBMS, Scheme
from hashlib import sha256
from matplotlib import pyplot as plt

# TODO: generic benchmarking function that can be called and configured for specific benchmarks
def benchmark(scheme_keygen, scheme_sign, scheme_verify):
    t_keygen_start = time.time()
    sks, pk, paths = scheme_keygen(385410)  # random epoch 1
    t_keygen = time.time() - t_keygen_start

    (blockhash, epoch) = (bytes.fromhex("eafbdd75941e56f899b2b4cda6959f2b3ddfce8cb1a4d78843ba86730913d493"), 385420)

    t_sign_start = time.time()
    sig = scheme_sign(blockhash, epoch) # sign an Ethereum block hash at epoch 1
    t_sign = time.time() - t_sign_start

    t_verify_start = time.time()
    scheme_verify((pk, sig), blockhash, pk)
    t_verify = time.time() - t_verify_start

    return (t_keygen, t_sign, t_verify)

HBMS_SCHEME = HBMS(H=lambda x: x, n=256, N=10, w=32, k=5)

H = sha256
n = 256
N = 1

times = []
for w, k in [(w, k) for w in [8, 16, 32, 64, 128, 256] for k in [10, 12, 14, 16, 18, 20]]:
    print(f"Benchmarking with w={w}, k={k}")
    scheme = Scheme(HBMS(H=sha256, n=256, N=1, w=w, k=k))
    times.append(benchmark(scheme.keygen, scheme.sign, scheme.verify))

plt.plot([w for w, k in [(w, k) for w in [8, 16, 32, 64, 128, 256] for k in [10, 12, 14, 16, 18, 20]]], [t[0] for t in times], label='Keygen Time')
plt.plot([w for w, k in [(w, k) for w in [8, 16, 32, 64, 128, 256] for k in [10, 12, 14, 16, 18, 20]]], [t[1] for t in times], label='Sign Time')
plt.plot([w for w, k in [(w, k) for w in [8, 16, 32, 64, 128, 256] for k in [10, 12, 14, 16, 18, 20]]], [t[2] for t in times], label='Verify Time')
plt.xlabel('w')
plt.ylabel('Time (s)')
plt.legend()
plt.savefig('graphs/w.png')

plt.plot([k for w, k in [(w, k) for w in [8, 16, 32, 64, 128, 256] for k in [10, 12, 14, 16, 18, 20]]], [t[0] for t in times], label='Keygen Time')
plt.plot([k for w, k in [(w, k) for w in [8, 16, 32, 64, 128, 256] for k in [10, 12, 14, 16, 18, 20]]], [t[1] for t in times], label='Sign Time')
plt.plot([k for w, k in [(w, k) for w in [8, 16, 32, 64, 128, 256] for k in [10, 12, 14, 16, 18, 20]]], [t[2] for t in times], label='Verify Time')
plt.xlabel('k')
plt.ylabel('Time (s)')
plt.legend()
plt.savefig('graphs/k.png')
