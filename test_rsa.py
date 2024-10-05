import rsa_simulator as rsa
PRIMES = (61, 53)

def main():
    public_key, private_key = rsa.generate_rsa_keys(PRIMES, verbose=True)
    test_message = "Hello, World!"
    encrypted_message = rsa.encrypt(test_message, public_key)
    decrypted_message = rsa.decrypt(encrypted_message, private_key)
    print(f"\nStep 5: We can now encrypt and decrypt alternating the keys. So one for encrypt, another to decrypt")
    print(f"Message: \"{test_message}\"")
    print(f"Encrypted: {encrypted_message}. (As string: \"{''.join(chr(number) for number in encrypted_message)}\")")
    print(f"Decrypted: \"{decrypted_message}\"")

    assert test_message == decrypted_message, f"Decrypted message is different from the original message. Expected: \"{test_message}\", got: \"{decrypted_message}\""
    print("\nTest passed successfully!")

if __name__ == '__main__':
    main()