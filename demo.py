#!/usr/bin/env python3

from encryption import encrypt, decrypt


PLAIN_TEXT = "Bob wants to talk to Alice!"

# Encryption example
cipher_text = encrypt(PLAIN_TEXT)
print(f"Encrypted: {cipher_text}")

# Decryption example
plain = decrypt(cipher_text)
print(f"Plain Text {plain}")
