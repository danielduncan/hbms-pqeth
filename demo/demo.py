from individual import generate_key, sign_message
from aggregation import aggregate_signatures, verify_signature

# TODO: demo script
# TODO: print results at each step
def main():
    # take some input message to validate
    message = "placeholder"

    # TODO: generate some validator keys
    keys = [generate_key() for _ in range(10)]

    # TODO: sign message with keys
    signatures = [(pk, sign_message(sk, message)) for (pk, sk) in keys]

    # TODO: aggregate signatures
    aggregated_signature = aggregate_signatures(signatures)

    # TODO: verify aggregated signature
    valid = verify_signature(aggregated_signature, message)

    # TODO: print final result, time, and signature size (compare with an without aggregation)
    print(f"{'valid' if valid else 'invalid'} signature")

if __name__ == "__main__":
    main()