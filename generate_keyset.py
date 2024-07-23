#!/usr/bin/env python3

import sys
import tink
from tink import aead
from tink import cleartext_keyset_handle

# Register all AEAD implementations
aead.register()

# Generate a new keyset handle for AEAD
try:
    key_template = aead.aead_key_templates.AES256_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
except tink.TinkError as e:
    print(f'Error creating primitive: {e}')
    sys.exit(1)

# Write the keyset to a file in a cleartext format (for demonstration purposes only)
keyset_filename = 'keyset.json'

# TODO:  DeprecationWarning: JsonKeysetWriter is deprecated
try:
    with open(keyset_filename, 'wt') as keyset_file:
        cleartext_keyset_handle.write(
            tink.JsonKeysetWriter(keyset_file), keyset_handle)
except tink.TinkError as e:
    print(f'Error creating primitive: {e}')
    sys.exit(1)



print(f"Keyset written to '{keyset_filename}'")
