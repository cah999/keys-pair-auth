import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from dotenv import load_dotenv

load_dotenv()


def main(key_option: str):
    if key_option == "RSA":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    else:
        private_key = ec.generate_private_key(ec.SECP384R1())

    private_key_pass = bytes(
        os.getenv("PASSPHRASE"),
        encoding="utf-8"
    )

    encrypted_pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass)
    )

    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_key_file = open(f"{option}_key.pem", "w")
    private_key_file.write(encrypted_pem_private_key.decode())
    private_key_file.close()

    public_key_file = open(f"{option}_key.pub", "w")
    public_key_file.write(pem_public_key.decode())
    public_key_file.close()


if __name__ == '__main__':
    option = input("Choose the key type (RSA/EC): ")
    if option.lower() == "rsa":
        main("RSA")
        print("RSA keys have been generated")
    elif option.lower() == "ec":
        main("EC")
        print("EC keys have been generated")
    else:
        print("Invalid option")
