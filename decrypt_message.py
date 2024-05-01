import base64

import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization


def decrypt_message(encrypted_message: str, private_key_path: str) -> str:
    with open(private_key_path, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=b'super_secret_password',
            backend=crypto_default_backend()
        )

    private_key = rsa.PrivateKey.load_pkcs1(private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ), format='DER')

    decrypted_message = rsa.decrypt(base64.b64decode(encrypted_message), private_key)

    return decrypted_message.decode()


if __name__ == '__main__':
    message = input("Enter the encrypted message: ")
    print(decrypt_message(
        message,
        "example-rsa.pem"))
