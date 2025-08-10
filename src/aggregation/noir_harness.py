import subprocess
import os
import toml
from typing import List, Tuple, Dict, Any
from pathlib import Path
from src import n, w, l, k
from demo import validators, strlen

class NoirHarness:
    def __init__(self):
        self.dir = Path("zkp")
        self.prover = self.dir / "Prover.toml"

        self.N = validators # number of sigs
        self.W = w # chunk length
        self.L = l # number of sigs
        self.K = k # Merkle tree depth
        self.STRLEN = strlen # length of message
        self.HASHLEN = n // 8 # length of hash output in bytes
    
    def prover_format(self, message: str, signatures: List[Tuple]) -> Dict[str, Any]:
        noir_message = list(message.encode('ascii'))

        noir_sigs = []
        noir_pks = []
        
        for pk, sig in signatures:
            index, wots_sig, path = sig

            noir_sig = [index, 
                        [list(sig) for sig in wots_sig],
                        [list(p) for p in path]]
            noir_sigs.append(noir_sig)

            noir_pks.append(list(pk))

        return {
            "message": noir_message,
            "sigs": noir_sigs,
            "pks": noir_pks
        }
    
    def execute_circuit(self, message: str, signatures: List[Tuple]) -> Dict[str, Any]:
        try:
            # generate prover TOML
            data = self.prover_format(message, signatures)
            # write to Prover.toml
            with open(self.prover, 'w') as f:
                f.write(toml.dumps(data))

            # change to the ZKP directory
            original_dir = os.getcwd()
            os.chdir(self.dir)
            
            try:
                # execute Noir
                cmd = ["nargo", "execute"]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60 # 60s
                )

                return {
                    "success": result.returncode == 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode
                }
                
            finally:
                # return
                os.chdir(original_dir)

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "timeout",
                "stdout": "",
                "stderr": "timeout after 60s",
                "returncode": -1
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": str(e),
                "returncode": -1
            }
    