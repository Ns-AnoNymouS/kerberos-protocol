import os
import json
import random
import string
import base64
import requests
from datetime import datetime
from flask import Flask, jsonify, request
from pymongo import MongoClient
from Crypto.Cipher import AES

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
client = MongoClient("mongodb://localhost:27017/")
db = client["cc"]
user = db["user"]
service = db["service"]


def get_tgs_secret_key(user_name):
    # geting the shared secret of tgs and as
    print("Getting shared secret of TGS and AS using ECC...")
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    public_number = public_key.public_numbers()

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    response = requests.post(
        "http://localhost:8989/kinit",
        json={"username": user_name, "public_key": pem_public_key.decode("utf-8")},
    )
    response_json = response.json()
    if response_json.get("status") == "USER EXISTS":
        print("User already exists!")
        return

    pem_tgt_public_key = response_json.get("public_key")
    tgt_public_key = serialization.load_pem_public_key(
        pem_tgt_public_key.encode("utf-8"), backend=default_backend()
    )
    iv = bytes.fromhex(response_json.get("iv"))
    shared_secret = private_key.exchange(ec.ECDH(), tgt_public_key)
    print("Public Key (x, y):", (public_number.x, public_number.y))
    print("Shared Secret:", shared_secret.hex())

    secret_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requires 32 bytes
        salt=None,
        info=None,
        backend=default_backend(),
    ).derive(shared_secret)

    return secret_key, iv


@app.post("/authenticate")
def authentication_server():
    user_name = request.json.get("username")
    payload = base64.b64decode(request.json.get("payload"))

    print("\nReceived Request: ")
    print(json.dumps(request.json, indent=2))

    # check the user in the control database
    user_data = user.find_one({"username": user_name})
    if user_data is None:
        return jsonify({"status": "User not found!"}), 404

    # get the secret key and iv of the user from the database and convert iv to bytes
    iv = bytes.fromhex(user_data.get("iv"))
    shared_secret = user_data.get("password")

    # derive the secret key from the shared secret
    secret_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requires 32 bytes
        salt=None,
        info=None,
        backend=default_backend(),
    ).derive(shared_secret.encode("utf-8"))

    # decrypt the payload with the secret key
    print("\nDecrypting payload with user's password...")
    decryption_suite = AES.new(secret_key, AES.MODE_CFB, iv)
    decrypted_payload = decryption_suite.decrypt(payload)
    decrypted_payload = json.loads(decrypted_payload)
    print("Decrypted Payload:", json.dumps(decrypted_payload, indent=2))

    service_name = decrypted_payload.get("service_id")
    nw_addr = decrypted_payload.get("nw_addr")
    lifetime_of_tgt = decrypted_payload.get("lifetime_of_tgt")

    # Generate SK1 for communication between client and TGS
    print("\nGenerating SK1 for communication between client and TGS.")
    sk1 = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    sk1 = sk1.encode("utf-8")
    new_iv = os.urandom(16)
    print("SK1: ", sk1.decode("utf-8"))

    # create payload to encrypt and send
    auth_ack_payload = {
        "service_id": str(service_name),
        "timestamp": str(datetime.now()),
        "lifetime": str(lifetime_of_tgt),
        "SK1": sk1.decode("utf-8"),
        "iv": new_iv.hex(),
    }
    print("\nAcknowledgement Payload:", json.dumps(auth_ack_payload, indent=2))

    tgt_payload = {
        "username": str(user_name),
        "service_id": str(service_name),
        "timestamp": str(datetime.now()),
        "nw_addr": str(nw_addr),
        "lifetime": str(lifetime_of_tgt),
        "SK1": sk1.decode("utf-8"),
        "iv": new_iv.hex(),
    }
    print("Ticket Granting Ticket Payload: ", json.dumps(tgt_payload, indent=2))

    # encrypt auth_ack_payload with user's secret key which is generated from users password
    print("\nEncrypting Acknowledgement with user's password...")
    auth_encryption_suite = AES.new(secret_key, AES.MODE_CFB, iv)
    auth_ack = auth_encryption_suite.encrypt(
        json.dumps(auth_ack_payload).encode("utf-8")
    )
    auth_ack = base64.b64encode(auth_ack).decode("utf-8")
    print("Encrypted Acknowledgement:", auth_ack)

    # encrypt tgt_payload with TGS secret key
    print(
        "\nEncrypting Ticket Granting Ticket (TGT) using shared secret (between TGS and AS)..."
    )
    tgs_secret_key, tgs_iv = get_tgs_secret_key(user_name)
    tgt_encryption_suite = AES.new(tgs_secret_key, AES.MODE_CFB, tgs_iv)
    tgt = tgt_encryption_suite.encrypt(json.dumps(tgt_payload).encode("utf-8"))
    tgt = base64.b64encode(tgt).decode("utf-8")
    print("Encrypted Ticket Granting Ticket (TGT):", tgt)

    response = jsonify(
        {
            "ack": auth_ack,
            "tgt": tgt,
        }
    )
    print("\nAcknowledgement and Ticket Granting Ticket sent to %s" % nw_addr)
    print("Response: ", response.json)
    print()

    return response


if __name__ == "__main__":
    app.run(debug=True, port=6969)
