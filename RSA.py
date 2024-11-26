import random
from sympy import isprime, randprime
from math import gcd
from typing import Tuple, List

def generate_keys(key_size: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Generate RSA public and private key pairs.
    
    Args:
        key_size: Bit length of the RSA modulus (n). Default is 1024 bits.
    
    Returns:
        Tuple containing ((e, n), (d, n)) - public and private key pairs
    """
    # Generate two large prime numbers
    p = randprime(2**(key_size//2-1), 2**(key_size//2))
    q = randprime(2**(key_size//2-1), 2**(key_size//2))
    n = p * q
    phi = (p - 1) * (q - 1)

    # Common value for e
    e = 65537  # Using fixed e=65537 as it's computationally efficient and secure
    if gcd(e, phi) != 1:
        raise ValueError("Key generation failed. Please try again.")

    # Calculate private key
    d = pow(e, -1, phi)
    
    return (e, n), (d, n)

def encrypt_message(message: str, public_key: Tuple[int, int]) -> List[int]:
    """
    Encrypt a message using RSA public key with simple padding.
    
    Args:
        message: String message to encrypt
        public_key: Tuple containing (e, n)
    
    Returns:
        List of encrypted integers
    """
    if not message:
        raise ValueError("Message cannot be empty")
        
    e, n = public_key
    try:
        # Add random padding to each character
        message_ascii = [ord(char) for char in message]
        padded_messages = []
        for m in message_ascii:
            if m >= n:
                raise ValueError("Message characters too large for given key size")
            # Add random padding in the higher bits
            padding = random.getrandbits(64) << 8  # 64 bits of padding
            padded_m = padding | m  # Combine padding and message
            padded_messages.append(padded_m)
        return [pow(m, e, n) for m in padded_messages]
    except Exception as exc:
        raise ValueError(f"Encryption failed: {str(exc)}")

def decrypt_message(ciphertext: List[int], private_key: Tuple[int, int]) -> str:
    """
    Decrypt a message using RSA private key, removing padding.
    
    Args:
        ciphertext: List of encrypted integers
        private_key: Tuple containing (d, n)
    
    Returns:
        Decrypted message string
    """
    if not ciphertext:
        raise ValueError("Ciphertext cannot be empty")
        
    d, n = private_key
    try:
        decrypted_values = [pow(c, d, n) for c in ciphertext]
        # Remove padding by taking only the last 8 bits
        original_ascii = [value & 0xFF for value in decrypted_values]
        return ''.join(chr(m) for m in original_ascii)
    except Exception as exc:
        raise ValueError(f"Decryption failed: {str(exc)}")

# Example usage
if __name__ == "__main__":
    try:
        # Generate keys with 1024-bit security
        public_key, private_key = generate_keys(1024)
        print(f"Public Key (e, n): {public_key}")
        print(f"Private Key (d, n): {private_key}")

        # Message to encrypt
        message = "Hello Information Security 9A"
        print(f"\nOriginal Message: {message}")

        # Encrypt and decrypt
        ciphertext = encrypt_message(message, public_key)
        print(f"Ciphertext: {ciphertext}")

        decrypted_message = decrypt_message(ciphertext, private_key)
        print(f"Decrypted Message: {decrypted_message}")

        # Verify correctness
        assert decrypted_message == message, "Decryption failed!"
        print("\nMessage encryption and decryption were successful.")
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")