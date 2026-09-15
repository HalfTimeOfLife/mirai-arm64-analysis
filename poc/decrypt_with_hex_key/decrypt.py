#!/usr/bin/env python3

import argparse
import sys

from Crypto.Cipher import AES


def hex_string_to_bytes(hex_input):
    if len(hex_input) != 0x20:
        return None

    try:
        decoded = bytes.fromhex(hex_input)
    except ValueError:
        return None

    if len(decoded) != 0x10:
        return None

    return decoded


def aes128_cbc_decrypt(key_bytes, encrypted_data):
    if len(encrypted_data) < 0x10:
        return None

    if len(encrypted_data) % 0x10 != 0:
        return None

    iv = encrypted_data[:0x10]
    ciphertext = encrypted_data[0x10:]

    if len(ciphertext) == 0:
        return None

    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    plaintext_with_padding = cipher.decrypt(ciphertext)

    padding_length = plaintext_with_padding[-1]

    if not 1 <= padding_length <= 16:
        return None

    padding = bytes([padding_length]) * padding_length

    if plaintext_with_padding[-padding_length:] != padding:
        return None

    return plaintext_with_padding[:-padding_length]


def decrypt_hex_string(key_bytes, hex_input):
    input_length = len(hex_input)

    if input_length <= 0x1F or input_length % 2 != 0:
        return None

    try:
        decoded_buffer = bytes.fromhex(hex_input)
    except ValueError:
        return None

    return aes128_cbc_decrypt(key_bytes, decoded_buffer)


def decrypt_with_hex_key(key_hex, encrypted_hex):
    key_bytes = hex_string_to_bytes(key_hex)

    if key_bytes is None:
        return None

    return decrypt_hex_string(key_bytes, encrypted_hex)


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypt an AES-128-CBC hex string.")

    parser.add_argument("key", help="AES key encoded as 32 hexadecimal characters")
    parser.add_argument("encrypted", help="Encrypted data encoded as hexadecimal")

    args = parser.parse_args()

    plaintext = decrypt_with_hex_key(args.key, args.encrypted)

    if plaintext is None:
        print("Decryption failed", file=sys.stderr)
        return 1

    print("Plaintext bytes:", plaintext)
    print("Plaintext hex:", plaintext.hex())

    try:
        print("Plaintext text:", plaintext.decode("utf-8"))
    except UnicodeDecodeError:
        print("Plaintext text: <not valid UTF-8>")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
