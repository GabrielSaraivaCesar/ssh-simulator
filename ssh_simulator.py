"""
This simulator is a SSH protocol simulator, focusing on authentication with RSA, a signed Diffie-Hellman key exchange, 
and an integrity check using a simple HMAC simulation.

RSA: 
- The server generates a public and private key pair using distinct prime numbers.
- The client generates a public and private key pair using distinct prime numbers.
- The server sends a challenge to the client.
- The client signs the challenge with its private key.
- The server verifies the signature with the client's public key.

Diffie-Hellman:
- The server generates a private secret and a public value.
- The client generates a private secret and a public value.
- The server signs the public value.
- The client verifies the server's public value signature.
- Both compute the shared session key. They must match.

SSH Session:
- The client sends an encrypted command to the server using the shared session key and an HMAC.
- The server decrypts the command and verifies the HMAC. The hashed message must match with the received HMAC.
- The server responds to the 'ls' command with a fake list of files.
- The client decrypts the response and verifies the HMAC. The hashed message must match with the received HMAC.
"""
import random
import hashlib
import time
from rsa_simulator import generate_rsa_keys, encrypt, decrypt

# Step 1: Generate client and server keys with distinct primes
CLIENT_PRIMES = (4583, 6833)
SERVER_PRIMES = (2017, 7723)
CLIENT_PUBLIC_KEY, CLIENT_PRIVATE_KEY = generate_rsa_keys(CLIENT_PRIMES)
SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY = generate_rsa_keys(SERVER_PRIMES)

# Mock list of files to send as a response to 'ls'
FAKE_LIST_FILES = "    file1.txt\n    file2.txt\n    directory1/"

# Diffie-Hellman parameters (shared publicly)
BASE = 5
MODULUS = 23  # A small prime number for example, but in practice this should be much larger

def print_with_delay(message, delay=.3):
    time.sleep(delay)
    print('\n-----------------\n',message)

def generate_challenge():
    return str(random.randint(1000, 9999))

def client_sign_challenge(challenge):
    return encrypt(challenge, CLIENT_PRIVATE_KEY)

def server_verify_signature(challenge, signature):
    decrypted_challenge = decrypt(signature, CLIENT_PUBLIC_KEY)
    return decrypted_challenge == challenge

def generate_diffie_hellman_key_pair():
    private_secret = random.randint(2, MODULUS - 2)
    public_value = pow(BASE, private_secret, MODULUS)
    return private_secret, public_value

def compute_shared_secret(their_public_value, my_private_secret):
    return pow(their_public_value, my_private_secret, MODULUS)

def symmetric_encrypt(message, session_key):
    return ''.join(chr((ord(char) + session_key) % 256) for char in message)

def symmetric_decrypt(encrypted_message, session_key):
    return ''.join(chr((ord(char) - session_key) % 256) for char in encrypted_message)

def simple_hmac(message, session_key):
    # Simple HMAC using SHA-256 (for simulation purposes)
    return hashlib.sha256((message + str(session_key)).encode()).hexdigest()

def ssh_handshake():
    print_with_delay("\n[SSH Handshake]")

    challenge = generate_challenge()
    print(f"Server: Challenge is '{challenge}'")

    signature = client_sign_challenge(challenge)
    print(f"Client: Signature is {signature}")

    is_valid = server_verify_signature(challenge, signature)

    if is_valid:
        print("Server: Signature is valid. Client authenticated successfully!")
        return True
    else:
        print("Server: Signature verification failed. Client authentication failed.")
        return False

def diffie_hellman_key_exchange():
    print("\n[Diffie-Hellman Key Exchange]")

    # Server generates its DH key pair
    server_private_secret, server_public_value = generate_diffie_hellman_key_pair()
    # Server signs the DH public value
    dh_signature = encrypt(str(server_public_value), SERVER_PRIVATE_KEY)
    print(f"Server: Generated DH public value {server_public_value} and signed it.")

    # Client generates its DH key pair
    client_private_secret, client_public_value = generate_diffie_hellman_key_pair()
    print(f"Client: Generated DH public value {client_public_value}")

    # Server sends DH public value and signature to client
    print("\nExchange public DH values between client and server...")
    
    # Client verifies server's DH public value
    print("\nClient: Verifying server's DH public value signature...")
    decrypted_dh_value = decrypt(dh_signature, SERVER_PUBLIC_KEY)
    if decrypted_dh_value == str(server_public_value):
        print("Client: Signature of DH value is valid.")
    else:
        print("Client: Signature verification failed.")
        return None

    # Both compute the shared session key
    server_shared_secret = compute_shared_secret(client_public_value, server_private_secret)
    client_shared_secret = compute_shared_secret(server_public_value, client_private_secret)

    print(f"\nServer: Computed shared secret (session key): {server_shared_secret}")
    print(f"Client: Computed shared secret (session key): {client_shared_secret}")

    assert server_shared_secret == client_shared_secret, "Shared secrets do not match!"
    print("\nShared secret successfully established!")

    return server_shared_secret

def ssh_session():
    print_with_delay("\n[SSH Session Start]")

    session_key = diffie_hellman_key_exchange()
    if session_key is None:
        print("Session key exchange failed.")
        return

    command = "ls"
    print_with_delay(f"\nClient: Sending command '{command}' encrypted with session key...")
    encrypted_command = symmetric_encrypt(command, session_key)
    command_hmac = simple_hmac(command, session_key)
    print(f"Client: Encrypted command is '{encrypted_command}' with HMAC {command_hmac}")

    # Server decrypts the command and checks integrity with HMAC
    print_with_delay("\nServer: Decrypting the command and verifying HMAC...")
    received_command = symmetric_decrypt(encrypted_command, session_key)
    received_hmac = simple_hmac(received_command, session_key)

    if received_hmac == command_hmac:
        print(f"Server: Received command is '{received_command}' and HMAC is valid.")
    else:
        print("Server: HMAC verification failed. Message integrity compromised.")
        return

    # Server responds to 'ls' command
    if received_command == "ls":
        response = FAKE_LIST_FILES
        encrypted_response = symmetric_encrypt(response, session_key)
        response_hmac = simple_hmac(response, session_key)
        print(f"Server: Encrypted response is '{encrypted_response}' with HMAC {response_hmac}")

        # Client decrypts the response and checks integrity
        print_with_delay("\nClient: Decrypting the response and verifying HMAC...")
        decrypted_response = symmetric_decrypt(encrypted_response, session_key)
        decrypted_response_hmac = simple_hmac(decrypted_response, session_key)

        if decrypted_response_hmac == response_hmac:
            print(f"Client: HMAC is valid. Decrypted response is:\n\n{decrypted_response}")
        else:
            print("Client: HMAC verification failed. Message integrity compromised.")

def ssh_simulator():
    authenticated = ssh_handshake()

    if authenticated:
        ssh_session()
    else:
        print("SSH Session could not be established due to authentication failure.")

if __name__ == "__main__":
    ssh_simulator()
