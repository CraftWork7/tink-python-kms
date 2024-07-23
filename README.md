# Google Tink Library Demo
Simple demo to showcase of using Tink Library with either local keyset or Cloud provided KMS.

Based on your configuration, you can utilize one of the following KMS providers:
* local keysite file
* Google Cloud KMS
* AWS KMS
* Oracle OCI Vault
* HashiCorp Vault

1. Setup the environment
```
python3 -m venv venv
source venv/bin/activate
pip install tink google-cloud-kms boto3 oci hvac
```

2. Generate the keyset
```
python genereate_keyset.py
```

3. Run the demo
```
python demo.py
```

## KMS Config Examples

Only one type of KSM provider can be used at a time. Below are a few examples.

### Local keyset
```
config = {
    'keyset_file': 'keyset.json'
}
```

### Google Cloud KMS Config
```
config = {
    'gcp_kms_uri': 'your_gcp_kms_uri',
    'gcp_credentials_file': 'path_to_gcp_credentials.json'
}
```

### AWS Config
```
config = {
     'aws_kms_arn': 'your_aws_kms_arn'
}
```

###  Oracle OCI Vault
```
config = {
    'oci_vault_id': 'your_oci_vault_id',
    'oci_config_file': 'path_to_oci_config_file'
}
```

###  HashiCorp Vault
```
config = {
    'vault_address': 'https://your_hashicorp_vault_address',
    'vault_token': 'your_hashicorp_vault_token',
    'vault_secret_path': 'path_to_your_secret_in_vault'
}
```
