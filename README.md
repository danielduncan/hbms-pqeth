# hbms-pqeth

Based on https://eprint.iacr.org/2025/055.pdf and the Rust implementation https://github.com/b-wagn/hash-sig, hbms-pqeth is a highly modular, simple (hence Python) proof of concept, created to demonstrate and explain the implementation of hash-based multi-signatures.

## Breakdown

src is split into the individual signature scheme, and the public aggregation process.

WOTS is Winternitz One-Time Signature. These form the basis of the post-quantum hash-based multi-signatures.

WOTS are combined with XMSS (eXtended Merkle Signature Scheme) for relatively compact signatures.

Aggregation to be done with pqSNARKs.
