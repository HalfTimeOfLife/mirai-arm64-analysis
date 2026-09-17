# poc/

This folder contains Python scripts reimplementing the functions I understood during the analysis, as proof of concept.

- [`decrypt_with_hex_key/`](decrypt_with_hex_key/): Reimplementation of the AES-128-CBC decryption routine found at `0x004032e0`.
- [`command-dispatch/`](command-dispatch/): Reimplementation of the C2 command dispatch logic. *(WIP)*