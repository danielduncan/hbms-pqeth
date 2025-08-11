"""
Refer to the github to install liboqs.
https://github.com/open-quantum-safe/liboqs-python
"""

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
Message must be a byte string.
Returns a dictionary with the list of sign times and verification times.
algo must be one defined by the liboqs library. 
"""
def time_sign_verif(algo = default_algo, msg = b"hello world",num_iterations = 50):
    #Try to open an existing pk/sk pair, if it does not exist, generate one.
    try:
        with open("sphincs_pk.bin", "rb") as f:
            pk = f.read()
        with open("sphincs_sk.bin", "rb") as f:
            sk = f.read()
    except FileNotFoundError:
        oqs_keygen(algo)
        with open("sphincs_pk.bin", "rb") as f:
            pk = f.read()
        with open("sphincs_sk.bin", "rb") as f:
            sk = f.read()
    
    #Create a signer with the provided sk
    signer = oqs.Signature(algo, secret_key= sk)
    print("Algorithm:", signer.details)

    
    # Sign and verify multiple times and record durations
    start = time.perf_counter()
    for _ in range(num_iterations):
        signature = signer.sign(msg)
    end = time.perf_counter()
    sign_time = (start-end)/num_iterations
    
    start = time.perf_counter()
    for _ in range(num_iterations):
        start = time.perf_counter()
        valid = signer.verify(msg, signature, pk)
    end = time.perf_counter()
    verify_time = (start-end)/num_iterations
    
    assert valid, "Verification step failed"
    #If the signatures are not valid, something must have gone wrong.
    
    return {"sign_times": sign_time,"verify_times": verify_time, "length" : signer.details['length_signature'], "sk_len" : signer.details['length_secret_key'] , "pk_len" : signer.details['length_public_key']}


#Example benchmarking script for sphincs+, can be made flexible to compare other schemes.
def example_benchmark():
    #Regenerate keys before running test sets. This is especially true if you have changed the algorithm.
    oqs_keygen()
    res = time_sign_verif()
    num_iterations = 50
    sign_times = res["sign_times"]
    verify_times = res["verify_times"]
    print(f"Average signing time:  {sign_times * 1000:.2f} ms")
    print(f"Average verify time:   {verify_times * 1000:.2f} ms")

if __name__ == "__main__":
    example_benchmark()
