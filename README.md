# Cryptography-Key-Exchange-Algorithms

## Overview
Python implementations of foundational cryptographic algorithms, including Diffie-Hellman, ElGamal, and RSA, for secure communications. These include:

- **Diffie-Hellman**: A key exchange algorithm that allows two parties to establish a shared secret over an insecure channel.
- **ElGamal**: A public-key cryptosystem that provides both encryption and digital signatures.
- **RSA**: A widely-used asymmetric cryptographic algorithm for secure data transmission.

## Features
- Modularized Python implementations of cryptographic algorithms.
- Simulation of key exchange and encryption/decryption processes.
- Educational comments for better understanding of cryptographic concepts.
- Licensed under the MIT License.

## Algorithms

### 1. Diffie-Hellman Key Exchange
The Diffie-Hellman algorithm allows two parties to securely generate a shared secret over a public channel. The implementation includes:
- Prime modulus and generator generation.
- Private and public key calculation.
- Shared secret derivation.

Usage:
```bash
python Diffie-Hellman.py
```

### 2. ElGamal Encryption and Decryption
The ElGamal algorithm provides public-key encryption based on discrete logarithms. The implementation includes:
- Key generation (public and private keys).
- Message encryption with padding.
- Decryption to recover the original message.

Usage:
```bash
python ElGamal.py
```

