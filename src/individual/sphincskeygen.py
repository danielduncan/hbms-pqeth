import oqs

#Define the algorithm used from liboqs.
algo = "SPHINCS+-SHAKE-256f-robust+"

with oqs.Signature(algo) as signer:
    print("Algorithm:", signer.details)

    # Generate a keypair
    pk = signer.generate_keypair()
    sk = signer.export_secret_key()
    print(f"Public key length: {len(pk)} bytes")
    print(f"Secret key length: {len(sk)} bytes")

    # Message to sign
    message = b"Hello Ethereum"
    
    # Sign the message
    signature = signer.sign(message)
    print(f"Signature length: {len(signature)} bytes")

    # Verify the signature
    valid = signer.verify(message, signature, pk)
    print("Signature valid:", valid)