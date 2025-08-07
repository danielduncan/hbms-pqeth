import oqs
import time

#Define the algorithm used from liboqs.
algo = "SPHINCS+-SHA2-256f-simple"
"""
Use this to show what signature schemes are supported by liboqs
print(oqs.get_enabled_sig_mechanisms())
"""
def oqs_keygen(algo):
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


oqs_keygen(algo)