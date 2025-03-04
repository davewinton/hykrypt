import argparse
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from os import urandom, path
from getpass import getpass

# Constants
KDF_KEY_LEN = 32
KDF_N = 2 ** 18
KDF_R = 8
KDF_P = 2

# Flags
derive_custom_key: bool = False


def create_keypair(key_path):
    """Create an RSA key pair"""
    valid_sizes = [2048, 3072, 4096, 8192]
    default_size = 2048

    while True:
        try:
            user_input = input(f"Set key size [{', '.join(map(str, valid_sizes))}] (default: {default_size}): ").strip()
            n_bits = int(user_input) if user_input else default_size
            if n_bits in valid_sizes:
                break
            print(f"[!] Invalid selection. Choose from: {', '.join(map(str, valid_sizes))}")
        except ValueError:
            print("[!] Please enter a valid number.")

    print("[*] Generating keypair...")
    key = RSA.generate(n_bits)

    while True:
        passwd = getpass("Enter password: ")
        confirm_passwd = getpass("Confirm password: ")
        if confirm_passwd == passwd:
            break
        print("[!] Passwords did not match")

    with open(key_path, "wb") as f:
        f.write(key.export_key(passphrase=passwd,
                               pkcs=8,
                               protection='PBKDF2WithHMAC-SHA512AndAES256-CBC'))

    with open(key_path + ".pub", "wb") as f:
        f.write(key.public_key().export_key())

    print("[+] Keypair generated.")


def derive_key(passwd: str, salt: bytes):
    """Derive a custom encryption key with Scrypt KDF"""
    print("[*] Deriving custom encryption key...")
    print("Note: Store the following parameters to derive key for future use..")
    print("=== Scrypt KDF params ===")
    print(f"Salt:{salt.hex()}\n"
          f"Key Length:{KDF_KEY_LEN}\n"
          f"N:{KDF_N}\n"
          f"r:{KDF_R}\n"
          f"p:{KDF_P}\n")

    return scrypt(passwd, salt, key_len=KDF_KEY_LEN, N=KDF_N, r=KDF_R, p=KDF_P)


def get_pvt_key(key_path):
    """Returns an RSA.RsaKey object containing the Private Key"""
    with open(key_path, "rb") as f:
        data = f.read()

    for _ in range(3):
        try:
            passwd = getpass("Enter private key passphrase: ")
            return RSA.import_key(data, passphrase=passwd)
        except (ValueError, TypeError):
            print("[!] Incorrect passphrase. Try again.")

    print("[!] Too many incorrect attempts. Exiting.")
    exit(1)


def get_pub_key(key_path) -> RSA.RsaKey | None:
    """Returns a RSA.RsaKey object containing the Public Key"""
    if path.exists(key_path):
        with open(key_path, "rb") as f:
            return RSA.import_key(f.read())
    return None


def rsa_encrypt(plaintext, pub_key) -> bytes:
    """RSA Encryption using PKCS1_0AEP"""
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(plaintext)


def rsa_decrypt(ciphertext, pvt_key) -> bytes:
    """RSA Decryption using PKCS1_0AEP"""
    cipher = PKCS1_OAEP.new(pvt_key)
    return cipher.decrypt(ciphertext)


def rsa_sign(message: bytes, pvt_key: RSA.RsaKey) -> bytes:
    """Sign a message with an RsaKey private key"""
    h = SHA256.new(message)
    return pss.new(pvt_key).sign(h)


def rsa_verify(message: bytes, pub_key: RSA.RsaKey, sig: bytes) -> bool:
    """Verify a message with an RsaKey public key"""
    h = SHA256.new(message)
    msg_verifier = pss.new(pub_key)
    try:
        msg_verifier.verify(h, sig)
        print("[+] Cryptographic signature verified!")
        return True
    except ValueError:
        return False


def aes_eax_encrypt(plaintext, key):
    """Authenticated encryption with AES-256-EAX"""
    cipher = AES.new(key, AES.MODE_EAX, mac_len=16)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext


def aes_eax_decrypt(ciphertext, key):
    """Authenticated decryption with AES-256-EAX"""
    nonce, tag, ciphertext = ciphertext[:16], ciphertext[16:32], ciphertext[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        print("[*] Checking the integrity of ciphertext..")
        cipher.verify(tag)
        print("[+] Successfully verified ciphertext!")
        return plaintext, True
    except ValueError:
        return b'', False


def hybrid_encrypt(plaintext: bytes,
                   pub_key: RSA.RsaKey,
                   signing_key: RSA.RsaKey = None) -> str:
    """Hybrid encryption using RSA and AES-EAX"""
    # Derive aes_key
    if derive_custom_key:
        while True:
            passwd = getpass("Enter password for KDF: ")
            if getpass("Confirm password") == passwd:
                aes_key = derive_key(passwd, urandom(32))
                break
            print("[!] Passwords don't match, try again..")
    else:
        aes_key = urandom(32)

    enc_aes_key = rsa_encrypt(aes_key, pub_key)
    ciphertext = aes_eax_encrypt(plaintext, aes_key)

    # Sign the encrypted key if a signing key is provided
    sig = b""
    if signing_key:
        sig = rsa_sign(enc_aes_key, signing_key)
        header = b'\x01'  # Signed message
    else:
        header = b'\x00'  # Unsigned message

    print("[+] Encryption complete! Outputting ciphertext..")

    try:
        # Combine header, encrypted key, signature (if any), and ciphertext
        return base64.b64encode(header + enc_aes_key + sig + ciphertext).decode()
    except ValueError as e:
        print(e)
        quit(1)


def hybrid_decrypt(ciphertext, pvt_key, pub_key=None) -> bytes | None:
    """Hybrid decryption using RSA and AES-EAX"""
    sig_size = 0
    enc_key_size = pvt_key.size_in_bytes()
    ciphertext = base64.b64decode(ciphertext)

    # Extract the header and ensure it indicates a signed message
    header = ciphertext[0:1]
    if header == b'\x00':
        print("[*] No signature, proceeding with decryption...")
        sig_size = 0
        ciphertext = ciphertext[1:]
    elif header == b'\x01':
        if not pub_key:
            print("[*] No PUBKEY for verification.. Skipping verification")
        else:
            print("[*] Signature present, verifying integrity...")
        sig_size = pub_key.size_in_bytes()
        ciphertext = ciphertext[1:]
    else:
        raise ValueError("[!] Invalid header, unable to proceed.")

    # Extract enc_aes_key, sig and ciphertext chunks from ciphertext block
    enc_aes_key, sig, ciphertext = (ciphertext[:enc_key_size],
                                    ciphertext[enc_key_size:enc_key_size + sig_size],
                                    ciphertext[enc_key_size + sig_size:])

    # If header indicates signed, verify the signature
    if header == b'\x01' and pub_key:
        if not rsa_verify(enc_aes_key, pub_key, sig):
            raise ValueError("[!] Signature verification failed.")

    # Decrypt the aes_key
    aes_key = rsa_decrypt(enc_aes_key, pvt_key)
    if aes_key is None:
        raise ValueError("[!] RSA decryption of AES key failed.")

    # Decrypt and verify the ciphertext
    plaintext, verified = aes_eax_decrypt(ciphertext, aes_key)
    if not verified:
        print("[!] Decryption failed. Integrity check failed.")
        exit(1)

    print("[+] Decryption complete! Outputting plaintext..")
    return plaintext


def main():
    global derive_custom_key
    parser = argparse.ArgumentParser(description="Hybrid Encryption CLI")
    parser.add_argument("-sK", "--signing-key", help="Signing key (Senders PVT_KEY)")
    parser.add_argument("-vK", "--verify-key", help="Verification key (Senders PUB_KEY)")
    parser.add_argument('--derive-key', action="store_true", help="Derive a custom key for AES encryption")
    parser.add_argument("-c", "--create-keypair", metavar="KEY_PATH", help="Generate an RSA key pair")
    parser.add_argument("-e", "--encrypt", metavar="PUB_KEY", help="Encrypt input using the specified public key")
    parser.add_argument("-d", "--decrypt", metavar="PVT_KEY", help="Decrypt input using the specified private key")
    parser.add_argument("-i", "--input", metavar="INPUT", help="Specify input text or file path")
    parser.add_argument("-o", "--output", metavar="OUTPUT", help="Specify output file path")
    args = parser.parse_args()

    if args.create_keypair:
        create_keypair(args.create_keypair)

    elif args.encrypt and args.input:
        if args.derive_key:
            derive_custom_key = True
        # Get signing key
        signing_key = None
        if args.signing_key:
            print("[*] Importing private key for signing.. Get ready to enter password")
            signing_key = get_pvt_key(args.signing_key)
            if not signing_key:
                print("[!] Private key not found.")
                exit(1)
        print("[*] Importing recipients public key..")
        pub_key = get_pub_key(args.encrypt)
        if not pub_key:
            print("[!] Public key not found.")
            exit(1)

        print("[+] Keys successfully imported!")

        input_data = args.input if path.exists(args.input) else args.input.encode()
        if path.exists(args.input):
            with open(args.input, "rb") as f:
                input_data = f.read()

        ciphertext = hybrid_encrypt(input_data, pub_key, signing_key)
        if args.output:
            with open(args.output, "w") as f:
                f.write(ciphertext)
        else:
            print(f"\n=== Encrypted Output ===\n{ciphertext}")

    elif args.decrypt and args.input:
        # Get verify-key
        verify_key = None
        if args.verify_key:
            print("[*] Importing public key for verification..")
            verify_key = get_pub_key(args.verify_key)
            if not verify_key:
                print("[!] Verify key not found.")
                exit(1)

        # Get private key
        print("[*] Importing private key for decryption..")
        pvt_key = get_pvt_key(args.decrypt)
        if not pvt_key:
            print("[!] Private key not found.")
            exit(1)

        print("[+] Keys successfully imported!")

        encrypted_data = args.input if path.exists(args.input) else args.input.encode()
        if path.exists(args.input):
            with open(args.input, "r") as f:
                encrypted_data = f.read()

        decrypted = hybrid_decrypt(encrypted_data, pvt_key, verify_key)
        if args.output:
            with open(args.output, "wb") as f:
                f.write(decrypted)
        else:
            print(f"\n=== Decrypted Output ===\n{decrypted.decode()}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
