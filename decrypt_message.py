import base64

import rsa
from cryptography.hazmat.primitives import serialization as crypto_serialization, serialization
from cryptography.hazmat.backends import default_backend as crypto_default_backend, default_backend
from rsa import PrivateKey


def decrypt_message(encrypted_message: str, private_key_path: str) -> str:
    with open(private_key_path, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=b'12',
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
    print(decrypt_message(
        """
GpEpOdHYMzNSukg41RI10Hnj9uSSCoKdK6sddJTECVlN0YwwPl5poAr4rgB3jMIcA49xpbI0F10CcD2t1HykYkyqk77cQEAmx7nbEPk6fC58UNVF9vV68QkP1LrqgepZXxFs/cQDH5IxF14Rwiz942G+sNuA50ilKYcq3mRxi6q7ICFM08oy8lX3ENnk3mpzexscffssbQzsRBeXZ1rRudYGDHGHKqH2mwmseK0ekavgC+JASL0cxB8i7NL3Bz5R0ncTJ1l78kkzPhAqOL7NwB7JW/iq5+Nm4PyagYpinbLww2+Yt3tk/SksPO4knH5GOfshORkoAJ7tFnIAYbM39g==""",
        "example-rsa.pem"))
