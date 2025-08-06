from time import time
from src.individual.keygen import generate_key
from src.individual.sign import sign_message
from src.aggregation.aggregate import aggregate_signatures
from src.individual.verify import verify_signature

# TODO: demo script
# TODO: print results at each step
def main():
    # take some input message (pretend this is a block in the Ethereum context) to validate
    message = "placeholder"

    # TODO: generate some validator keys
    keys = [generate_key(r, time(), 2 ** 32 - 1) for r in range(10)]

    # TODO: sign message with keys
    signatures = [(pk, sign_message(sk, message)) for (sk, pk) in keys]

    # TODO: aggregate signatures
    aggregated_signature = aggregate_signatures(signatures)

    # TODO: verify aggregated signature
    valid = verify_signature(aggregated_signature, message)

    # TODO: print final result, time, and signature size (compare with an without aggregation)
    print(f"{'valid' if valid else 'invalid'} signature")

if __name__ == "__main__":
    main()