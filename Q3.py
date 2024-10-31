import random
import sys

def check_prime(num):
    """
    Checks if a number is prime.
    
    Parameters:
    - num (int): The number to check for primality.
    
    Raises:
    - ValueError: If num is not a prime number.
    """
    # Handle negatives, 0, and 1
    if num <= 1:
        raise ValueError("Both p and q need to be prime numbers.")
    # Check divisibility and factors to determine if prime
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            raise ValueError("Both p and q need to be prime numbers.")

def gcd(a, b):
    """
    Compute the greatest common divisor using Euclid's algorithm.
    
    Parameters:
    - a (int): First integer
    - b (int): Second integer
    
    Returns:
    - int: The greatest common divisor of a and b.
    """
    # Euclid's algorithm to calculate GCD
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """
    Compute the modular inverse of e modulo phi using the Extended Euclidean Algorithm.
    
    Parameters:
    - e (int): The exponent to find the inverse of.
    - phi (int): The modulus.
    
    Returns:
    - int: The modular inverse of e modulo phi.
    """
    # Initiaalize variables
    original_phi = phi
    x, y, u, v = 0, 1, 1, 0
    # Calculate modular inverse using extended euclidean algorithm
    while e != 0:
        q, r = phi // e, phi % e
        m, n = x - u * q, y - v * q
        phi, e, x, y, u, v = e, r, u, v, m, n
    # Add phi if negative
    if x < 0:
        x += original_phi
    return x

def generate_keypair(p, q):
    """
    Generate a public and private keypair using two prime numbers.
    Select the smallest possible e that is coprime with phi.
    
    Parameters:
    - p (int): A prime number.
    - q (int): Another prime number.
    
    Returns:
    - tuple: Tuple containing the public and private keys. e.g. ((e, n), (d, n))
    """
    # Calculate modulus
    n = p * q
    # Calculate phi
    phi = (p - 1) * (q - 1)
    # Find e (between 1 and phi)
    e = 2
    while e < phi and gcd(e, phi) != 1:
        e += 1
    # Calculate d using modular inverse
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    """
    Encrypt a plaintext string using a public key.
    
    Parameters:
    - pk (tuple): The public key.
    - plaintext (str): The text to encrypt.
    
    Returns:
    - list: A list of integers representing the encrypted message.
    """
    # Split public key tuple
    key, n = pk
    # Encrypt text
    cipher = [(ord(char) ** key) % n for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    """
    Decrypt a list of integers back into a string using a private key.
    
    Parameters:
    - pk (tuple): The private key.
    - ciphertext (list): The encrypted message as a list of integers.
    
    Returns:
    - str: The decrypted message.
    """
    # Split public key tuple
    key, n = pk
    # Decrypt text
    plain = [chr((char ** key) % n) for char in ciphertext]
    return ''.join(plain)

def main():
    """
    Main function to execute RSA-like encryption and decryption based on command line inputs.
    """
    try:
        # Checks to make sure there are a correct number of arguments
        if len(sys.argv) != 4:
            raise ValueError("Usage: python Q3.py <prime_p> <prime_q> <message>")
        p = sys.argv[1]
        # Checks to make sure p is an integer
        if not p.isdigit():
            raise ValueError("Only integer values are allowed.")
        p = int(p)

        q = sys.argv[2]
        # Checks to make sure q is an integer
        if not q.isdigit():
            raise ValueError("Only integer values are allowed.")
        q = int(q)

        # Checks to make sure both p and q are greater than 10
        if p <= 10 or q <= 10:
            raise ValueError("Both p and q need to be greater than 10.")
        # Checks to make sure p and q are not equal
        if p == q:
            raise ValueError("p and q cannot be equal.")
        
        # Check if p and q are prime
        check_prime(p)
        check_prime(q)

        message = sys.argv[3]

        public, private = generate_keypair(p, q)
        print("Public key is", public)
        print("Private key is", private)

        encrypted_msg = encrypt(public, message)
        print("Encrypted message is:")
        print(''.join(map(lambda x: str(x), encrypted_msg)))
        print("Decrypted message is:")
        print(decrypt(private, encrypted_msg))
    except ValueError as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
