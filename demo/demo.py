from time import time, time_ns
from src.individual.keygen import generate_key
from src.individual.sign import sign_message
from src.aggregation.aggregate import aggregate_signatures
from src.individual.verify import verify_signature

# TODO: demo script
# TODO: print results at each step
def main():
    # take some input message (pretend this is a block in the Ethereum context) to validate
    message = "placeholder"
    print(f"Message to validate: {message}")

    validators = 5
    print(f"Generating keypairs for {validators} validators")
    time_start = time()
    keys = [generate_key() for _ in range(validators)]
    print(f"Generated {len(keys)} keys in {time() - time_start} seconds:")
    for i, (sk, pk) in enumerate(keys):
        print(f"Validator {i}\n\t pk: {pk.hex()}\n\t sk: {sk.hex()}")

    print("Signing message with sk")
    time_start = time()
    signatures = [(pk, sign_message(sk, message)) for (sk, pk) in keys]
    print(f"Signed message with {len(signatures)} signatures in {time() - time_start} seconds")

    # TODO: aggregate signatures
    # aggregated_signature = aggregate_signatures(signatures)

    # TODO: verify signatures
    for pk, sig in signatures:
        print(f"Verifying signature with pk: {pk.hex()} and sig: {sig.hex()}")
        time_start = time()
        print(f"Signature valid: {verify_signature(sig, message, pk)}")
        print(f"Verification took {time() - time_start} seconds")
    
    # valid = verify_signature(aggregated_signature, message, )

    # TODO: print final result, time, and signature size (compare with an without aggregation)
    print(f"{'valid' if valid else 'invalid'} signature")

if __name__ == "__main__":
    main()