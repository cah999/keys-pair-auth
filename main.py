import base64

from cryptography.hazmat.primitives import serialization as crypto_serialization, serialization
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
import rsa

app = FastAPI()
users: dict[str, bytes] = {}


class RegisterUser(BaseModel):
    login: str
    qwe: str


@app.post("/register")
def register_user(user_login: str, public_key: UploadFile = File(...)):
    if user_login in users:
        raise HTTPException(status_code=400, detail="User already exists")
    users[user_login] = public_key.file.read()
    return {"message": "User has been registered"}


class GetEncryptedMessage(BaseModel):
    login: str


@app.post("/message")
def get_encrypted_message(user_login: str, public_key: UploadFile = File(...)):
    if user_login not in users:
        raise HTTPException(status_code=400, detail="User does not exist")
    public_key = serialization.load_pem_public_key(
        public_key.file.read(),
        backend=crypto_default_backend()
    )
    public_key_der = public_key.public_bytes(
        encoding=crypto_serialization.Encoding.DER,
        format=crypto_serialization.PublicFormat.PKCS1
    )
    public_key = rsa.PublicKey.load_pkcs1(public_key_der, format='DER')
    encrypted_message = rsa.encrypt("Hello, World!".encode(), public_key)
    return {"message": base64.b64encode(encrypted_message).decode()}


class LoginUser(BaseModel):
    login: str
    decrypted_message: str


@app.post("/login")
def login(login_user: LoginUser):
    if login_user.login not in users:
        raise HTTPException(status_code=400, detail="User does not exist")
    decrypted_message = login_user.decrypted_message
    original_message = "Hello, World!"
    if decrypted_message != original_message:
        raise HTTPException(status_code=400, detail="Invalid message")
    return {"message": "User has been logged in"}


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
