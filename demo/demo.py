from time import time, time_ns
from src.individual.keygen import generate_key, xmss_keygen
from src.individual.sign import sign_message, xmss_sign
# from src.aggregation.aggregate import aggregate_signatures
from src.individual.verify import verify_signature, xmss_verify
from src.individual import k, l
from random import randint

def main():
    # take some input message (pretend this is a block in the Ethereum context) to validate
    message = "placeholder message for demo"
    w = -(len(message) // -l)
    message = message.ljust(w * l, ' ') # pad to multiple of l - in prod message would be fixed length
    print(f"Message to validate: {message}")

    validators = 3
    print(f"Generating keypairs for {validators} validators")
    time_start = time()
    keys = [xmss_keygen() for _ in range(validators)]
    print(f"Generated {len(keys)} keys in {time() - time_start:.3f} seconds:")

    for validator in keys:
        print(f"Validator {keys.index(validator)} has public key {validator[1].hex()} and secret keys:")
        for i, slot in enumerate(validator[0]):
            for j, sk in enumerate(slot):
                print(f"\t sk {i * len(slot) + j}: {sk.hex()}")


    print("Each validator now signs the message")
    time_start = time()
    signatures = []
    for validator in keys:
        slots = validator[0]
        index = randint(0, k) # randomly select a slot to use
        pk = validator[1]
        path = validator[2]
        signatures.append((pk, xmss_sign(slots, index, message, path)))


    print(f"Signed message with {validators} validators in {time() - time_start} seconds")
    print("Verifying individual signatures")
    for i, (pk, sig) in enumerate(signatures):
        print(f"Verifying validator {i}'s signatures:")
        time_start = time()
        print(f"\t Public key: {pk.hex()}")
        print(f"\t Signature: {[s.hex() for s in sig[1]]}")
        print(f"\t Path: {[p.hex() for p in sig[2]]}")
        print(f"\t Signature valid: {xmss_verify(sig, message, pk)}")
        print(f"\t Verification took {time() - time_start:.3f} seconds")

    # TODO: aggregate signatures
    # aggregated_signature = aggregate_signatures(signatures)

    # TODO: verify aggregated signature
    # valid = verify_signature(aggregated_signature, message)

if __name__ == "__main__":
    main()