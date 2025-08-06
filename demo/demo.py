from time import time, time_ns
from src.individual.keygen import generate_key
from src.individual.sign import sign_message
# from src.aggregation.aggregate import aggregate_signatures
from src.individual.verify import verify_signature

def main():
    # take some input message (pretend this is a block in the Ethereum context) to validate
    message = "placeholder".ljust(64, ' ')
    print(f"Message to validate: {message}")

    validators = 3
    print(f"Generating keypairs for {validators} validators")
    time_start = time()
    keys = [generate_key() for _ in range(validators)]
    print(f"Generated {len(keys)} keys in {time() - time_start} seconds:")

    for validator in keys:
        print(f"Validator {keys.index(validator)} has keypairs:")
        for sk, pk in validator:
            print(f"\t pk: {pk.hex()}\n\t sk: {sk.hex()}")


    print("Each validator now signs the message")
    time_start = time()
    signatures = []
    for validator in keys:
        sk = [sk for sk, _ in validator]
        pk = [pk for _, pk in validator]
        signatures.append((pk, sign_message(sk, message)))

    print(f"Signed message with {len(signatures)} signatures in {time() - time_start} seconds")

    print("Verifying individual signatures")
    for i, (pk, sig) in enumerate(signatures):
        print(f"Verifying validator {i}'s signature:")
        time_start = time()
        print(f"\t Signature valid: {verify_signature(sig, message, pk)}")
        print(f"\t Verification took {time() - time_start} seconds")

    # TODO: aggregate signatures
    # aggregated_signature = aggregate_signatures(signatures)

    # TODO: verify aggregated signature
    # valid = verify_signature(aggregated_signature, message)

if __name__ == "__main__":
    main()