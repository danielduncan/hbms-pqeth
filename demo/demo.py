from concurrent.futures import ThreadPoolExecutor
from time import time
from random import randint

from src.individual import k

from src.individual.keygen import xmss_keygen
from src.individual.sign import xmss_sign
from src.individual.verify import xmss_verify

def main():
    # take some input message (pretend this is a block in the Ethereum context) to validate
    epoch = randint(0, 100) # arbitrary epoch number
    message = "placeholder message for demo"
    print(f"Message to validate: {message}")

    validators = randint(2, 6)
    # concurrent validators
    print(f"Running with {validators} validators")
    with ThreadPoolExecutor() as executor:
        signatures = list(executor.map(lambda idx: validator(idx, epoch, message), range(validators)))

    print(f"Verifying individual signatures")
    for i, (pk, sig) in enumerate(signatures):
        print(f"Verifying validator {i}'s signatures:")
        time_start = time()
        print(f"\t Public key: {pk.hex()}")
        print(f"\t Signature (truncated): {[s.hex()[0:4] for s in sig[1]]}")
        print(f"\t Path (truncated): {[p.hex()[0:4] for p in sig[2]]}")
        print(f"\t Signature valid: {xmss_verify(sig, message, pk)}")
        print(f"\t Verification took {time() - time_start:.3f} seconds")

def validator(idx: int, epoch: int, message: str):
    current_epoch = epoch + 1 # aribitrary current epoch

    print(f"{idx}: generating keypairs")
    time_start = time()
    keys = xmss_keygen(current_epoch)
    print(f"{idx}: generated keys in {time() - time_start:.3f} seconds:")
    print(f"{idx}: has public key {keys[1].hex()}")

    print(f"{idx}: signing message")
    time_start = time()
    slots = keys[0]
    index = randint(0, k) # randomly select a slot to use TODO: make this epoch
    pk = keys[1]
    path = keys[2]
    sig = (pk, xmss_sign(slots, index, message, path))
    print(f"{idx}: signed message in {time() - time_start} seconds")
    return sig

if __name__ == "__main__":
    main()