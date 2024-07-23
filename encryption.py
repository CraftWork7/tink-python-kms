#!/usr/bin/env python3

import tink
from tink import aead, cleartext_keyset_handle, tink_config
from tink import secret_key_access
from tink.integration import gcpkms

import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

import oci

import hvac

#tink_config.register()

# Initialize Tink
aead.register()

# Function to initialize Tink with a local keyset file
def init_local_keyset(keyset_file: str):
    with open(keyset_file, 'rt') as f:
        keyset_handle = tink.json_proto_keyset_format.parse( f.read(),secret_key_access.TOKEN)
            
    return keyset_handle.primitive(aead.Aead)

# Function to initialize Tink with GCP KMS
def init_gcp_kms(kms_uri: str, credentials_file: str):
    gcp_client = gcpkms.GcpKmsClient(key_uri=kms_uri, credentials_path=credentials_file)
    aead.register_kms_client(gcp_client)
    keyset_handle = gcp_client.get_aead(kms_uri)
    return keyset_handle

# Function to initialize Tink with AWS KMS
def init_aws_kms(kms_arn: str):
    try:
        client = boto3.client('kms')
        key_material = client.generate_data_key(KeyId=kms_arn, KeySpec='AES_256')['Plaintext']
        keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(key_material.decode()))
        return keyset_handle.primitive(aead.Aead)
    except (NoCredentialsError, PartialCredentialsError) as e:
        raise e

# Function to initialize Tink with Oracle OCI Vault
def init_oci_vault(vault_id: str, oci_config_file: str):
    config = oci.config.from_file(oci_config_file)
    client = oci.key_management.KmsCryptoClient(config)
    key_material = client.generate_data_encryption_key(vault_id, oci.key_management.models.GenerateDataEncryptionKeyDetails(key_shape={"algorithm": "AES", "length": 256})).data.key_material
    keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(key_material.decode()))
    return keyset_handle.primitive(aead.Aead)

# Function to initialize Tink with HashiCorp Vault
def init_hashicorp_vault(vault_address: str, token: str, secret_path: str):
    client = hvac.Client(url=vault_address, token=token)
    key_material = client.secrets.kv.read_secret_version(path=secret_path)['data']['data']['key']
    keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(key_material.decode()))
    return keyset_handle

# Choose initialization method based on configuration
def get_aead_primitive(config: dict):
    if 'keyset_file' in config:
        return init_local_keyset(config['keyset_file'])
    elif 'gcp_kms_uri' in config and 'gcp_credentials_file' in config:
        return init_gcp_kms(config['gcp_kms_uri'], config['gcp_credentials_file'])
    elif 'aws_kms_arn' in config:
        return init_aws_kms(config['aws_kms_arn'])
    elif 'oci_vault_id' in config and 'oci_config_file' in config:
        return init_oci_vault(config['oci_vault_id'], config['oci_config_file'])
    elif 'vault_address' in config and 'vault_token' in config and 'vault_secret_path' in config:
        return init_hashicorp_vault(config['vault_address'], config['vault_token'], config['vault_secret_path'])
    else:
        raise ValueError("Invalid configuration for KMS initialization")

# Initialize the AEAD primitive based on settings (example usage)
config = {
    'keyset_file': 'keyset.json',
    # 'gcp_kms_uri': 'your_gcp_kms_uri',
    # 'gcp_credentials_file': 'path_to_gcp_credentials.json',
    # 'aws_kms_arn': 'your_aws_kms_arn',
    # 'oci_vault_id': 'your_oci_vault_id',
    # 'oci_config_file': 'path_to_oci_config_file',
    # 'vault_address': 'https://your_hashicorp_vault_address',
    # 'vault_token': 'your_hashicorp_vault_token',
    # 'vault_secret_path': 'path_to_your_secret_in_vault'
}
aead_primitive = get_aead_primitive(config)

def encrypt(data: str) -> str:
    ciphertext = aead_primitive.encrypt(data.encode(), b"")
    return ciphertext.hex()

def decrypt(ciphertext: str) -> str:
    decrypted_data = aead_primitive.decrypt(bytes.fromhex(ciphertext), b"")
    return decrypted_data.decode()
