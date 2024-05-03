import base64
import secrets
import string
import time
import traceback

import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel

app = FastAPI()
users: dict[str, bytes] = {}
original_messages: dict[str, tuple[str, float]] = {}


class RSALoginUser(BaseModel):
    login: str
    decrypted_message: str


class ECLoginUser(BaseModel):
    login: str
    encrypted_message: str


class GetEncryptedMessage(BaseModel):
    login: str


@app.post("/register")
def register_user(user_login: str, public_key: UploadFile = File(...)):
    if user_login in users:
        raise HTTPException(status_code=400, detail="User already exists")
    users[user_login] = public_key.file.read()
    return {"message": "User has been registered"}


@app.post("/rsa/message", description="Get encrypted message for RSA")
def get_rsa_encrypted_message(user: GetEncryptedMessage):
    if user.login not in users:
        raise HTTPException(status_code=400, detail="User does not exist")
    public_key = serialization.load_pem_public_key(
        users[user.login],
        backend=crypto_default_backend()
    )
    public_key_der = public_key.public_bytes(
        encoding=crypto_serialization.Encoding.DER,
        format=crypto_serialization.PublicFormat.PKCS1
    )

    public_key = rsa.PublicKey.load_pkcs1(public_key_der, format='DER')
    characters = string.ascii_letters + string.digits
    random_message = ''.join(secrets.choice(characters) for _ in range(128))
    encrypted_message = rsa.encrypt(random_message.encode(), public_key)

    original_messages[user.login] = (random_message, time.time())

    return {"message": base64.b64encode(encrypted_message).decode()}


@app.post("/rsa/login", description="Login using RSA")
def login(login_user: RSALoginUser):
    if login_user.login not in users:
        raise HTTPException(status_code=400, detail="User does not exist")
    decrypted_message = login_user.decrypted_message

    if login_user.login not in original_messages:
        raise HTTPException(status_code=400, detail="No message found for this user")

    original_message, message_time = original_messages[login_user.login]

    if time.time() - message_time > 60:
        del original_messages[login_user.login]
        raise HTTPException(status_code=400, detail="Message expired")

    if decrypted_message != original_message:
        raise HTTPException(status_code=400, detail="Invalid message")
    return {"message": "User has been logged in"}


@app.post("/ec/message", description="Get encrypted message for ECDSA")
def get_ec_encrypted_message(user: GetEncryptedMessage):
    if user.login not in users:
        raise HTTPException(status_code=400, detail="User does not exist")

    characters = string.ascii_letters + string.digits
    random_message = ''.join(secrets.choice(characters) for _ in range(128))
    print(f"generated {random_message}")
    original_messages[user.login] = (random_message, time.time())

    return {"message": random_message, "algorithm": "SHA256withECDSA"}


@app.post("/ec/login", description="Login using ECDSA")
def login_ec(login_user: ECLoginUser):
    if login_user.login not in users:
        raise HTTPException(status_code=400, detail="User does not exist")
    encrypted_message = login_user.encrypted_message

    original_message, message_time = original_messages[login_user.login]

    if time.time() - message_time > 60:
        del original_messages[login_user.login]
        raise HTTPException(status_code=400, detail="Message expired")

    public_key = serialization.load_pem_public_key(
        users[login_user.login],
        backend=crypto_default_backend()
    )
    try:
        print("Original message:", original_message, "Encrypted message:", encrypted_message, "Public key:", public_key)
        public_key.verify(
            data=bytes(original_message, encoding="utf-8"),
            signature=base64.b64decode(encrypted_message),
            signature_algorithm=ec.ECDSA(hashes.SHA256())
        )
    except Exception as e:
        print(traceback.format_exc())
        raise HTTPException(status_code=400, detail="Invalid message")
    return {"message": "User has been logged in"}


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
