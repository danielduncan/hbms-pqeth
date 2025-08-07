import oqs
import time

#Define the default algorithm used if not specified in function calls.
default_algo = "SPHINCS+-SHA2-256f-simple"
"""
Use this to show what signature schemes are supported by liboqs
print(oqs.get_enabled_sig_mechanisms())
"""

#generates a pk/sk pair and writes them to a file, use this if you need fixed keys for benchmarking.
def oqs_keygen(algo = default_algo):
    signer = oqs.Signature(algo)
    print("Algorithm:", signer.details)

    # Generate a keypair
    pk = signer.generate_keypair()
    sk = signer.export_secret_key()
    print(f"Public key length: {len(pk)} bytes")
    print(f"Secret key length: {len(sk)} bytes")
    with open("sphincs_pk.bin", "wb") as f:
        f.write(pk)
    with open("sphincs_sk.bin", "wb") as f:
        f.write(sk)

"""
time the signing and verification of an algorithm from liboqs (Default iterations is 50 iterations, and algorithm is defined above)
"""
def time_sign_verif(msg = "hello world",num_iterations = 50 ,algo = default_algo):
    #Try to open an existing pk/sk pair, if it does not exist, generate one.
    try:
        with open("sphincs_pk.bin", "rb") as f:
            pk = f.read()
        with open("sphincs_sk.bin", "rb") as f:
            sk = f.read()
    except FileNotFoundError:
        oqs(oqs_keygen(algo))
        with open("sphincs_pk.bin", "rb") as f:
            pk = f.read()
        with open("sphincs_sk.bin", "rb") as f:
            sk = f.read()
    signer = oqs.Signature(algo, secret_key= sk)
    print("Algorithm:", signer.details)
    sign_times = []
    verify_times = []
    

    signer.import_secret_key(sk)
    for _ in range(num_iterations):
        start = time.perf_counter()
        signature = signer.sign(msg)
        end = time.perf_counter()
        sign_times.append(end - start)

    # Verify multiple times and record durations
    for _ in range(num_iterations):
        start = time.perf_counter()
        valid = signer.verify(msg, signature, pk)
        end = time.perf_counter()
        verify_times.append(end - start)
    
    assert valid, "Verification step failed"
    return {"sign_times": sign_times,"verify_times": verify_times}

num_iterations = 50
res = time_sign_verif()
sign_times = res["sign_times"]
verify_times = res["verify_times"]
print(f"Average signing time:  {sum(sign_times) / num_iterations * 1000:.2f} ms")
print(f"Average verify time:   {sum(verify_times) / num_iterations * 1000:.2f} ms")