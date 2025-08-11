from src.scheme import HBMS, Scheme

import csv
import time
import string
import random
from hashlib import sha256

n = 50 # number of iterations
w = 128
l = 2
k = 5 # tree depth
message_length = 32

# TODO: generic benchmarking function that can be called and configured for specific benchmarks
def benchmark(scheme_keygen, scheme_sign, scheme_verify, setup_params):
    t_start = time.time()

    t_keygen_start = time.time()
    scheme_keygen(**setup_params)
    t_keygen = time.time() - t_keygen_start

    t_sign_start = time.time()
    scheme_sign(**setup_params)
    t_sign = time.time() - t_sign_start

    t_verify_start = time.time()
    scheme_verify(**setup_params)
    t_verify = time.time() - t_verify_start

    t_total = time.time() - t_start

    return (t_keygen, t_sign, t_verify, t_total)

def benchmark():
    t1 = 0
    t2 = 0
    for _ in range(n):
        # setup
        epoch = random.randint(0, 10000)
        index = random.randint(0, 2 ** k)
        message = ''.join(random.choices(string.ascii_letters + string.digits, k = message_length)).encode('ascii')
        SCHEME = HBMS(H=sha256, N=1, n=256, w=w, k=k)
        s = Scheme(SCHEME)
        sks, pk, paths = s.keygen(epoch)

        # xmss_sign
        start = time.perf_counter()
        slot, wots, path = s.sign(message, epoch)
        end = time.perf_counter()
        t1 += end - start

        sig = (pk, (index, wots, path))

        # xmss_verify
        start = time.perf_counter()
        valid = s.verify(sig, message, pk)
        end = time.perf_counter()
        t2 += end - start
    t1 /= n
    t2 /= n
    return [t1 * 1000, t2 * 1000]

with open('test/benchmarks/xmss_res.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['algorithm name',' sign time (ms)', ' verify time (ms)'])
    results = ['xmss'] + benchmark()
    writer.writerow(results)