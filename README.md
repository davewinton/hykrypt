# HyKrypt
Hybrid AES/RSA Encryption System written in Python

## Overview

This Python script provides a command-line interface (CLI) for hybrid encryption using RSA and AES-EAX. It supports generating RSA key pairs, encrypting and decrypting data, and optionally signing and verifying ciphertext integrity.

## Features

- **RSA Key Pair Generation:** Generates RSA key pairs with optional passphrase protection.
- **Hybrid Encryption:**
    - Encrypts data using AES-256 in EAX mode.
    - Encrypts AES key using RSA-OAEP.
- Supports optional signing of encrypted AES keys.
- **Hybrid Decryption:**
    - Decrypts AES key using RSA-OAEP.
    - Verifies message integrity via AES-EAX authentication.
- **Custom Key Derivation:**
    - Allows using Scrypt-based key derivation for AES encryption.
- Support for Text/ File input

## Installation

**Dependencies (install using pip):**

`pip install pycryptodome`

OR

`pip install -r requirements.txt`

## Usage

Run the script with the appropriate arguments to perform encryption, decryption, or key generation.

#### Generating an RSA Key Pair

`python hykrypt.py -c mykey.pem`

This will generate `mykey.pem` (private key) and `mykey.pem.pub` (public key). You will be prompted to set a passphrase.

#### Encrypting Data

```shell
python hykrypt.py \
-e mykey.pem.pub \
-i plaintext.txt \
-o encrypted.txt
```
Encrypts `plaintext.txt` using `mykey.pem.pub`.

Outputs base64-encoded ciphertext to `encrypted.txt`.

#### Encrypt with Signing

```shell
python hykrypt.py \
-e recipient.pub \
-sK sender_private.pem \
-i message.txt \
-o encrypted.txt
```

Uses sender's private key to sign the encrypted AES key.

#### Decrypting Data

```shell
python hykrypt.py \
-d mykey.pem \
-i encrypted.txt \
-o decrypted.txt
```

Decrypts `encrypted.txt` using `mykey.pem`.

Outputs the decrypted data to `decrypted.txt`.

#### Decrypt with Signature Verification

```shell
python hykrypt.py \
-d recipient.pem \
-vK sender.pub \
-i encrypted.txt \
-o decrypted.txt
```

Uses sender's public key to verify the integrity of the encrypted AES key before decryption.

#### Using a Custom Key for AES Encryption

`python hykrypt.py -e mykey.pem.pub -i message.txt --derive-key`

Uses a password-derived key for AES encryption.

## Security Considerations

- For educational use only
- Private keys should be stored securely and never shared.
- Always verify signatures when receiving encrypted messages.
- Use strong passwords for key protection.