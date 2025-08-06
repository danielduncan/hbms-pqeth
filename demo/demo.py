from time import time, time_ns
from src.individual.keygen import generate_key
from src.individual.sign import sign_message
# from src.aggregation.aggregate import aggregate_signatures
from src.individual.verify import verify_signature

def main():
    # take some input message (pretend this is a block in the Ethereum context) to validate
    message = "placeholder message for demo".ljust(32, ' ')
    print(f"Message to validate: {message}")

    validators = 3
    print(f"Generating keypairs for {validators} validators")
    time_start = time()
    keys = [generate_key() for _ in range(validators)]
    print(f"Generated {len(keys)} keys in {time() - time_start:.3f} seconds:")

    for validator in keys:
        print(f"Validator {keys.index(validator)} has public key {validator[1].hex()} and secret keys:")
        for sk in validator[0]:
            print(f"\t sk: {sk.hex()}")


    print("Each validator now signs the message")
    time_start = time()
    signatures = []
    for validator in keys:
        sks = validator[0]
        pk = validator[1]
        signatures.append((pk, sign_message(sks, message)))

    print(f"Signed message with {validators} validators in {time() - time_start} seconds")
    print("Verifying individual signatures")
    for i, (pk, sig) in enumerate(signatures):
        print(f"Verifying validator {i}'s signatures:")
        time_start = time()
        print(f"\t Signature valid: {verify_signature(sig, message, pk)}")
        print(f"\t Verification took {time() - time_start:.3f} seconds")

    # TODO: aggregate signatures
    # aggregated_signature = aggregate_signatures(signatures)

    # TODO: verify aggregated signature
    # valid = verify_signature(aggregated_signature, message)

if __name__ == "__main__":
    main()