import random
from typing import Tuple, List
from sympy import randprime

def generate_keys(key_size: int = 1024) -> Tuple[Tuple[int, int, int], int]:
    """
    Generate ElGamal public and private key pairs.
    
    Args:
        key_size: Bit length of the prime number q. Default is 1024 bits.
    
    Returns:
        Tuple containing ((q, g, h), private_key) - public and private components
    """
    # Generate a large prime number q
    q = randprime(2**(key_size-1), 2**key_size)
    
    # Find a generator g
    g = random.randint(2, q-1)
    
    # Generate private key
    private_key = random.randint(2, q-2)
    
    # Calculate public key h = g^private_key mod q
    h = pow(g, private_key, q)
    
    return ((q, g, h), private_key)

def encrypt_message(message: str, public_key: Tuple[int, int, int]) -> Tuple[List[int], int]:
    """
    Encrypt a message using ElGamal encryption with padding.
    
    Args:
        message: String message to encrypt
        public_key: Tuple containing (q, g, h)
    
    Returns:
        Tuple containing (encrypted_message, p)
    """
    if not message:
        raise ValueError("Message cannot be empty")
        
    q, g, h = public_key
    try:
        # Generate ephemeral key k
        k = random.randint(2, q-2)
        
        # Calculate shared parameter p = g^k mod q
        p = pow(g, k, q)
        
        # Calculate shared secret s = h^k mod q
        s = pow(h, k, q)
        
        encrypted_message = []
        for char in message:
            # Add random padding in higher bits
            padding = random.getrandbits(64) << 8
            padded_m = padding | ord(char)
            if padded_m >= q:
                raise ValueError("Message too large for given key size")
            # Encrypt: c = s * m mod q
            encrypted_char = (s * padded_m) % q
            encrypted_message.append(encrypted_char)
            
        return encrypted_message, p
    except Exception as exc:
        raise ValueError(f"Encryption failed: {str(exc)}")

def decrypt_message(encrypted_message: List[int], p: int, private_key: int, q: int) -> str:
    """
    Decrypt a message using ElGamal private key, removing padding.
    
    Args:
        encrypted_message: List of encrypted integers
        p: Public encryption parameter
        private_key: Private key for decryption
        q: Prime modulus
    
    Returns:
        Decrypted message string
    """
    if not encrypted_message:
        raise ValueError("Encrypted message cannot be empty")
        
    try:
        # Calculate shared secret s = p^private_key mod q
        s = pow(p, private_key, q)
        
        # Calculate modular multiplicative inverse of s
        s_inv = pow(s, -1, q)
        
        decrypted_chars = []
        for encrypted_char in encrypted_message:
            # Decrypt: m = c * s^(-1) mod q
            decrypted_value = (encrypted_char * s_inv) % q
            # Remove padding by taking only the last 8 bits
            original_char = decrypted_value & 0xFF
            decrypted_chars.append(chr(original_char))
            
        return ''.join(decrypted_chars)
    except Exception as exc:
        raise ValueError(f"Decryption failed: {str(exc)}")

def main():
    try:
        # Generate keys with 1024-bit security
        public_key, private_key = generate_keys(1024)
        q, g, h = public_key
        print(f"Public Key (q, g, h): {public_key}")
        print(f"Private Key: {private_key}")

        # Message to encrypt
        message = "Hello Information Security 9A"
        print(f"\nOriginal Message: {message}")

        # Encrypt and decrypt
        encrypted_message, p = encrypt_message(message, public_key)
        print(f"Encrypted Message: {encrypted_message}")
        print(f"Encryption Parameter (p): {p}")

        decrypted_message = decrypt_message(encrypted_message, p, private_key, q)
        print(f"Decrypted Message: {decrypted_message}")

        # Verify correctness
        assert decrypted_message == message, "Decryption failed!"
        print("\nMessage encryption and decryption were successful.")
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == '__main__':
    main()