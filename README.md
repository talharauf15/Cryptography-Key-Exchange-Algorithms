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

### 3. RSA Algorithm
The RSA algorithm facilitates secure data transmission using asymmetric keys. The implementation includes:
- Key generation (public and private key pairs).
- Message encryption and decryption.

Usage:
```bash
python RSA.py
```

## Prerequisites
- Python 3.7 or later
- `sympy` library

To install dependencies, run:
```bash
pip install sympy
```

## Getting Started
1. Clone the repository:
   ```bash
   git clone https://github.com/talharauf15/Cryptography-Key-Exchange-Algorithms.git
   cd Cryptography-Key-Exchange-Algorithms
   ```

2. Execute the desired script (e.g., for Diffie-Hellman):
   ```bash
   python Diffie-Hellman.py
   ```

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributions
Contributions are welcome! Feel free to open issues or submit pull requests to enhance the project.

## Author
[**Talha Rauf**](https://github.com/talharauf15)

---

**Disclaimer**: This project is for educational purposes only. It should not be used for production-level applications.
