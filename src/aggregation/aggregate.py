from typing import List, Tuple, Dict, Any

# signatures <- list of (pk, sig)
# sig <- (index, wots_sig, path)
# returns if circuit successfully executed and if the proof was successfully generated
def aggregate_signatures(harness, message: bytes, signatures: List[Tuple]) -> Dict[str, Any]:
    zkp = harness.execute_circuit(message, signatures)
    proof = harness.prove()

    return {
        "witness success": zkp["success"],
        "proof success": proof,
    }

def aggregate_verify(harness) -> bool:
    vk = harness.generate_vk()
    valid = harness.verify(vk)

    return valid
