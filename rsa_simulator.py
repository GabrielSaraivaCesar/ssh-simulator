"""
This is a simple RSA algorithm simulator. It generates the public and private keys and can encrypt and decrypt messages using them.
The center of the logic in this algorithm is a clever use of euler's totient function. https://en.wikipedia.org/wiki/Euler%27s_totient_function
"""
import math

# These primes are usually huge because it defines the strength of the keys, i'm using these just for demonstration purpuses
# They are also usually random

def euler_totient_function(prime1, prime2):
    return (prime1 - 1) * (prime2 - 1)


def find_relatively_prime(n):
    candidate = 2
    while True:
        if n % candidate == 0:
            candidate += 1
            continue 
        
        if math.gcd(n, candidate) == 1:
            break

        candidate += 1
    return candidate

def str_to_binary_string(string_value):
    return ''.join(format(ord(char), '08b') for char in string_value)

def binary_string_to_str(binary_string):
    chunks = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    return ''.join(chr(int(chunk, 2)) for chunk in chunks)

def encrypt_or_decrypt_number(number, key):
    return pow(number, key[1], key[0])


def encrypt(message, key):
    char_numbers = [ord(char) for char in message]
    encrypted_numeric = [encrypt_or_decrypt_number(char_number, key) for char_number in char_numbers]
    return encrypted_numeric

def decrypt(encrypted_numeric, key):
    decrypted_numeric = [encrypt_or_decrypt_number(encrypted_number, key) for encrypted_number in encrypted_numeric]
    return ''.join(chr(number) for number in decrypted_numeric)

def generate_rsa_keys(primes, verbose=False):
    if verbose:
        print(f"Step 1: Execution starts. Primes were randomly defined as {primes}")
    
    primes_product = primes[0] * primes[1]
    phi = euler_totient_function(primes[0], primes[1])
    if verbose:
        print(f"\nStep 2: primes are used to calculate their product ({primes_product}) and the φ value ({phi})")

    public_expoent = find_relatively_prime(phi)
    if verbose:
        print(f"\nStep 3: Find a relatively prime to φ, this will be the public expoent ({public_expoent})")

    private_expoent = pow(public_expoent, -1, phi)
    if verbose:
        print(f"\nStep 4: Find the private expoent ({private_expoent}) using the public expoent in the formula d ≡ e^(-1) (mod φ(n)). Here is a representation of the keys:")

    public_key = (primes_product, public_expoent)
    private_key = (primes_product, private_expoent)
    if verbose:
        print(f"public key: {public_key}\nprivate key: {private_key}")

    return public_key, private_key
