# load_encrypted_keyset.py

import tink
from tink import aead
from tink import cleartext_keyset_handle

# Register all AEAD implementations
tink.tink_config.register()

# Read the encrypted keyset from a file
encrypted_keyset_filename = 'encrypted_keyset.json'
with open(encrypted_keyset_filename, 'rb') as f:
    encrypted_keyset = f.read()

# Decrypt the keyset using the same passphrase and salt
passphrase = b'your_secure_passphrase_here'
salt = b'some_salt_here'
key_template = aead.aead_key_templates.create_aes_gcm_key_template(32)
keyset_encryption_handle = tink.new_keyset_handle(key_template)
aead_primitive = keyset_encryption_handle.primitive(aead.Aead)
decrypted_keyset = aead_primitive.decrypt(encrypted_keyset, salt)

# Load the decrypted keyset
keyset_handle = cleartext_keyset_handle.read(tink.BinaryKeysetReader(decrypted_keyset))

# Now you can use keyset_handle for encryption/decryption
aead_primitive = keyset_handle.primitive(aead.Aead)
