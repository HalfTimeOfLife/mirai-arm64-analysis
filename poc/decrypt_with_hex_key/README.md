# decrypt_with_hex_key

This folder contains a re-implementation of the function located at `0x004032e0`.

The function:

- Converts a 32-character hexadecimal key into 16 bytes.
- Decodes the encrypted hexadecimal input.
- Decrypts the data using AES-128-CBC.
- Removes the PKCS#7 padding.
- Returns the resulting plaintext.

## Usage

```bash
pip install pycryptodome
python decrypt.py <key_hex> <encrypted_hex>
```