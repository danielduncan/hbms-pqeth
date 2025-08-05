import time

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