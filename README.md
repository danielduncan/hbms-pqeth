# hbms-pqeth

Based on https://eprint.iacr.org/2025/055.pdf, hbms-pqeth is a highly modular, simple (hence Python) proof of concept, created to demonstrate and explain the implementation of hash-based multi-signatures. Furthermore, (not post-quantum) SNARK aggregation is demonstrated and implemented so different SNARKs can be used, for when pqSNARKs reach maturity.

# Setup

Install Python for WOTS and XMSS (https://www.python.org/downloads/), and Noir (https://noir-lang.org/docs/getting_started/quick_start) for SNARKs.

To install requirements: `pip install -r requirements.txt`

To run: `python -m demo.demo`

# Breakdown

src is split into the individual signature scheme, and the public aggregation process.

### Individual

WOTS is Winternitz One-Time Signature. These form the basis of the post-quantum hash-based multi-signatures.

WOTS are combined with XMSS (eXtended Merkle Signature Scheme) for relatively compact signatures.

### Aggregation

Multi-signature aggregation is achieved by generating succinct proofs of signature validity with SNARKs. The ZKP is implemented in Noir, a Domain Specific Language (DSL) for SNARKs. pqSNARKs are still in early stages and there exists no implementation which is well accepted to be secure. Therefore Noir was chosen for its versatility, allowing the proving backend to be changed with no alteration to the proof itself. Hence, when generally accepted to be post-quantum secure SNARKs are made available, they can be easily tested within this project.

A harness is used to run the ZKP in Noir with the Python code.
