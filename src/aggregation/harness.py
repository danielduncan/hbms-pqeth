import subprocess
import os
import toml
from typing import List, Tuple, Dict, Any
from pathlib import Path

class NoirHarness:
    def __init__(self, n: int, N: int, w: int, l: int, k: int):
        self.dir = Path("zkp")
        self.prover = self.dir / "Prover.toml"

        self.N = N # number of signatures
        self.LEN = n # bitlength of message/hash
        self.W = w # chunk width
        self.L = l # number of signatures
        self.K = k # Merkle tree depth

    def prover_format(self, message: bytes, signatures: List[Tuple]) -> Dict[str, Any]:
        noir_message = list(message)

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
            "N": self.N,
            "LEN": self.LEN,
            "W": self.W,
            "L": self.L,
            "K": self.K,
            "message": noir_message,
            "sigs": noir_sigs,
            "pks": noir_pks
        }

    def execute_circuit(self, message: bytes, signatures: List[Tuple]) -> Dict[str, Any]:
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
                # check the circuit, create Prover.toml
                cmd = ["nargo", "check"]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60 # 60s
                )
            
                if result.returncode != 0:
                    return {
                        "success": False,
                        "error": "nargo check failed",
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "returncode": result.returncode
                    }

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

    def prove(self) -> bool:
        try:
            cmd = ["bb", "prove", "-b", "./zkp/target/zkp.json", "-w", "./zkp/target/zkp.gz", "-o", "./zkp/target"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600 # 10 mins
            )

            return result.returncode == 0
        
        except subprocess.TimeoutExpired:
            return False

    def generate_vk(self) -> str:
        cmd = ["bb", "write_vk", "-b", "./zkp/target/zkp.json", "-o", "./zkp/target"]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600 # 10 mins
        )

        return str(self.dir / "target" / "vk")

    def verify(self, vk: str) -> bool:
        cmd = ["bb", "verify", "-k", vk, "-p", "./zkp/target/proof", "-i", "./zkp/target/public_inputs"]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60 # 60s
        )

        return result.returncode == 0
