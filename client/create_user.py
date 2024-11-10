import json
import base64
import socket
import requests
from time import sleep
from Crypto.Cipher import AES
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

password = "secret password"


def main():
    """
    Phase 1: Contact the Authentication Server by providing the user id or client id
    along with the service (here, tgs) id to obtain ticket for.
    """
    # construct the payload to send to authenticate server
    user_name = input("Enter user id to authenticate with: ")

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    response = requests.post(
        "http://localhost:6969/kinit",
        json={"username": user_name, "public_key": pem_public_key.decode("utf-8")},
    )
    response_json = response.json()
    if response_json.get("status") == "USER EXISTS":
        print("User already exists!")
        return
    pem_as_public_key = response_json.get("public_key")
    as_public_key = serialization.load_pem_public_key(
        pem_as_public_key.encode("utf-8"), backend=default_backend()
    )
    iv = bytes.fromhex(response_json.get("iv"))
    shared_secret = private_key.exchange(ec.ECDH(), as_public_key)

    secret_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requires 32 bytes
        salt=None,
        info=None,
        backend=default_backend(),
    ).derive(shared_secret)

    # print("Derived Secret Key:", secret_key.hex())
    # print("IV:", iv)

    encryption_suite = AES.new(secret_key, AES.MODE_CFB, iv)
    payload = {"password": password}
    encrypt_payload = encryption_suite.encrypt(json.dumps(payload).encode("utf-8"))
    payload = {
        "username": user_name,
        "payload": base64.b64encode(encrypt_payload).decode("utf-8"),
    }
    response = requests.post("http://localhost:6969/user", json=payload)
    if response.status_code != 200:
        print("User creation failed!")
        return

    data = {"username": user_name, "iv": iv.hex(), "password": password}
    with open("response.json", "w") as f:
        f.write(json.dumps(data))
    print("User created successfully!")


if __name__ == "__main__":
    main()
