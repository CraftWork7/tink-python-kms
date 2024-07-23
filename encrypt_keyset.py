#!/usr/bin/env python3

import tink
from tink import aead
from tink import cleartext_keyset_handle
from tink import tink_config

# Register all AEAD implementations
tink_config.register()

# Generate a new keyset handle for AEAD
key_template = aead.aead_key_templates.AES256_GCM
keyset_handle = tink.new_keyset_handle(key_template)

# Encrypt the keyset using a passphrase
passphrase = b'your_secure_passphrase_here'
salt = b'some_salt_here'  # Ensure this is generated securely and stored safely
key_template = aead.aead_key_templates.create_aes_gcm_key_template(32)
keyset_encryption_handle = tink.new_keyset_handle(key_template)
aead_primitive = keyset_encryption_handle.primitive(aead.Aead)
encrypted_keyset = aead_primitive.encrypt(cleartext_keyset_handle.to_binary(keyset_handle), salt)

# Save the encrypted keyset to a file
encrypted_keyset_filename = 'encrypted_keyset.json'
with open(encrypted_keyset_filename, 'wb') as f:
    f.write(encrypted_keyset)

print(f"Encrypted keyset written to {encrypted_keyset_filename}")
