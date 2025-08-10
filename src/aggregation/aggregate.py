from typing import List, Tuple, Dict, Any
from .noir_harness import NoirHarness

# signatures <- list of (pk, sig)
# sig <- (index, wots_sig, path)
# returns if circuit succeeded, if signatures are valid, and stdout/stderr
def aggregate_signatures(message: str, signatures: List[Tuple]) -> Dict[str, Any]:    
    harness = NoirHarness()
    result = harness.execute_circuit(message, signatures)
    
    return {
        "success": result["success"],
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
    }

# TODO: verify the actual aggregated signature
def aggregate_verify(signatures: List[Tuple], message: str) -> bool:
    harness = NoirHarness()
    result = harness.execute_circuit(message, signatures)

    return result["success"]
