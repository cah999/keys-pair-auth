import base64
import os

from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from dotenv import load_dotenv

load_dotenv()
private_key_pass = bytes(
    os.getenv("PASSPHRASE"),
    encoding="utf-8"
)


def sign_message(unsigned_message: str, private_key_path: str) -> str:
    with open(private_key_path, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=private_key_pass,
            backend=crypto_default_backend()
        )

    signed_message = private_key.sign(bytes(unsigned_message, 'UTF-8'), signature_algorithm=ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signed_message).decode()


if __name__ == '__main__':
    message = input("Enter the encrypted message: ")
    print(sign_message(
        message,
        "ec_key.pem"))
