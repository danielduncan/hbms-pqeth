from typing import List, Tuple, Dict, Any
from src.aggregation.harness import NoirHarness

# signatures <- list of (pk, sig)
# sig <- (index, wots_sig, path)
# returns if circuit succeeded, if signatures are valid, and stdout/stderr
def aggregate_signatures(message: str, signatures: List[Tuple]) -> Dict[str, Any]:    
    harness = NoirHarness()

    zkp = harness.execute_circuit(message, signatures)
    proof = harness.prove()

    
    return {
        "witness success": zkp,
        "proof success": proof,
    }

def aggregate_verify(signatures: List[Tuple]) -> bool:
    harness = NoirHarness()

    vk = harness.generate_vk()
    valid = harness.verify(vk)

    return valid
