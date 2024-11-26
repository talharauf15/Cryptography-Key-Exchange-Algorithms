import random
from sympy import randprime
from typing import Tuple

def generate_prime(bits: int = 64) -> int:
    """
    Generate a large prime number with the specified number of bits.
    
    Args:
        bits: Number of bits for the prime number. Default is 64 bits.
    
    Returns:
        A prime number of the specified bit length
    """
    return randprime(2**(bits-1), 2**bits)

def generate_parameters(prime_bits: int = 64) -> Tuple[int, int]:
    """
    Generate Diffie-Hellman parameters (prime modulus and generator).
    
    Args:
        prime_bits: Bit length of the prime number. Default is 64 bits.
    
    Returns:
        Tuple containing (prime modulus p, generator g)
    """
    p = generate_prime(prime_bits)
    g = 2  # Using 2 as a common generator
    return p, g

def generate_private_key(p: int) -> int:
    """
    Generate a private key for Diffie-Hellman.
    
    Args:
        p: Prime modulus
    
    Returns:
        A random private key between 1 and p-1
    """
    return random.randint(2, p - 2)

def calculate_public_key(p: int, g: int, private_key: int) -> int:
    """
    Calculate the public key using the private key and parameters.
    
    Args:
        p: Prime modulus
        g: Generator
        private_key: Private key
    
    Returns:
        Public key
    """
    if not 1 < private_key < p - 1:
        raise ValueError("Invalid private key")
    return pow(g, private_key, p)

def calculate_shared_secret(p: int, public_key: int, private_key: int) -> int:
    """
    Calculate the shared secret using the other party's public key and own private key.
    
    Args:
        p: Prime modulus
        public_key: Other party's public key
        private_key: Own private key
    
    Returns:
        Shared secret key
    """
    if not 1 < public_key < p:
        raise ValueError("Invalid public key")
    return pow(public_key, private_key, p)

def diffie_hellman_key_exchange(prime_bits: int = 64) -> None:
    """
    Perform a complete Diffie-Hellman key exchange simulation.
    
    Args:
        prime_bits: Bit length of the prime number. Default is 64 bits.
    """
    try:
        # Step 1: Generate parameters
        p, g = generate_parameters(prime_bits)
        print(f"System Parameters:")
        print(f"Prime (p): {p}")
        print(f"Generator (g): {g}\n")

        # Step 2: Generate private keys
        alice_private_key = generate_private_key(p)
        bob_private_key = generate_private_key(p)

        # Step 3: Calculate public keys
        alice_public_key = calculate_public_key(p, g, alice_private_key)
        bob_public_key = calculate_public_key(p, g, bob_private_key)

        print("Generated Keys:")
        print(f"Alice's Private Key: {alice_private_key}")
        print(f"Alice's Public Key: {alice_public_key}")
        print(f"Bob's Private Key: {bob_private_key}")
        print(f"Bob's Public Key: {bob_public_key}\n")

        # Step 4: Calculate shared secrets
        alice_shared_secret = calculate_shared_secret(p, bob_public_key, alice_private_key)
        bob_shared_secret = calculate_shared_secret(p, alice_public_key, bob_private_key)

        print("Shared Secrets:")
        print(f"Alice's Shared Secret: {alice_shared_secret}")
        print(f"Bob's Shared Secret: {bob_shared_secret}\n")

        # Verify that both parties derived the same secret
        assert alice_shared_secret == bob_shared_secret, "Shared secrets do not match!"
        print("✓ Shared Secret Key Exchange Successful!")

    except Exception as e:
        print(f"An error occurred during key exchange: {str(e)}")

if __name__ == "__main__":
    # Execute the Diffie-Hellman key exchange with 64-bit prime
    diffie_hellman_key_exchange(64)