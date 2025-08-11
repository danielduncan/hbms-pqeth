from hashlib import sha256
from time import time
from random import randint
from src.scheme import HBMS, Scheme


def main():
    lifetime = 4 # log2(lifetime of keypairs in epochs)
    N = 4 # number of validators

    # validating a recent Ethereum block https://etherscan.io/block/23110384
    (blockhash, epoch) = (bytes.fromhex("eafbdd75941e56f899b2b4cda6959f2b3ddfce8cb1a4d78843ba86730913d493"), 385420)
    print(f"Validating block hash {blockhash.hex()} at epoch {epoch}")

    SCHEME = HBMS(H=sha256, N=N, n=256, w=128, k=lifetime)

    print(f"{N} validators being created:")
    validators = []
    for _ in range(N):
        validators.append(Scheme(SCHEME))

    print(f"Validators created, now each generates their keys")
    for i, validator in enumerate(validators):
        time_start = time()
        validator.keygen(epoch)
        print(f"\t Validator {i}'s public key: {validator.pk.hex()} generated in {time() - time_start:.3f} seconds")

    print("Now each validator signs the block hash")
    signatures = []
    for i, validator in enumerate(validators):
        print(f"\t Validator {i} signing block hash")
        time_start = time()
        signatures.append((validator.pk, validator.sign(blockhash, epoch)))
        print(f"\t Validator {i} signed block hash in {time() - time_start:.3f} seconds")

    print("Now each verifies another signature")
    for i, validator in enumerate(validators):
        print(f"\t Validator {i} verifying validator {(i + 1) % N}'s signature")
        time_start = time()
        valid = validator.verify(signatures[(i + 1) % N], blockhash, validators[(i + 1) % N].pk)
        print(f"\t Verification took {time() - time_start:.3f} seconds, valid: {valid}")

    print("Now signatures are aggregated by a random validator using SNARKs")
    time_start = time()
    validator = validators[randint(0, N - 1)]
    try:
        result = validator.aggregate_signatures(blockhash, signatures)
        print(f"\t SNARKs took {time() - time_start:.3f} seconds")
        print(f"\t Witness success: {result['witness success']}, Proof success: {result['proof success']}")

    except Exception as e:
        print(f"\t Circuit execution failed with exception {e}")

    print(f"Now all validators verify the aggregated signature")
    for validator in validators:
        print(f"\t Validator {validator.pk.hex()} verifying aggregated signature")
        time_start = time()
        try:
            result = validator.aggregate_verify()
            print(f"\t Verification took {time() - time_start:.3f} seconds")
            print(f"\t Aggregated signature valid: {result}")

        except Exception as e:
            print(f"\t Verification failed with exception {e}")

if __name__ == "__main__":
    main()
