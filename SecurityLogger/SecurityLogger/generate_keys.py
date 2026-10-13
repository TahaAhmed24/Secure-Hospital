from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# Generate RSA key pair for server signing
def generate_server_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Save private key
    with open("server_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open("server_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Server keys generated.")

# Generate HMAC key
def generate_hmac_key():
    hmac_key = os.urandom(32)  # 256-bit secret
    with open("hmac_secret.key", "wb") as f:
        f.write(hmac_key)
    print("HMAC key generated.")


if __name__ == "__main__":
    generate_server_keys()
    generate_hmac_key()

