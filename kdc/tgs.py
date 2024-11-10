import os
import json
import base64
import random
import string
from datetime import datetime, timedelta
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
tgs_secret = {}


@app.post("/kinit")
def secret_generation():
    pem_user_public_key = request.json.get("public_key")
    user_name = request.json.get("username")
    user_public_key = serialization.load_pem_public_key(
        pem_user_public_key.encode("utf-8"), backend=default_backend()
    )

    print("Generating shared secret using ECC...")

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    public_number = public_key.public_numbers()
    shared_secret = private_key.exchange(ec.ECDH(), user_public_key)

    print("Public Key (x, y):", (public_number.x, public_number.y))
    print("Shared Secret:", shared_secret.hex())

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    iv = os.urandom(16)
    tgs_secret[user_name] = (shared_secret, iv)

    payload = {
        "status": "OK",
        "public_key": pem_public_key.decode("utf-8"),
        "iv": iv.hex(),
    }
    return payload


@app.post("/tickets")
def tgt_verify():
    user_name = request.json.get("username")
    authenticator = base64.b64decode(request.json.get("authenticator"))
    ticket_granting_ticket = base64.b64decode(
        request.json.get("ticket_granting_ticket")
    )

    print("\nReceived Request: ")
    print(json.dumps(request.json, indent=2))

    tgs_secret_key, tgs_iv = tgs_secret[user_name]
    secret_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend(),
    ).derive(tgs_secret_key)

    print("\nDecrypting TGT using shared secret (between TGS and AS)...")
    tgs_decrypt_suite = AES.new(secret_key, AES.MODE_CFB, tgs_iv)
    tgt_payload = tgs_decrypt_suite.decrypt(ticket_granting_ticket).decode("utf-8")
    tgt = json.loads(tgt_payload)
    print(tgt)

    sk1 = tgt["SK1"]
    sk1_iv = bytes.fromhex(tgt["iv"])

    sk1_secret_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend(),
    ).derive(sk1.encode("utf-8"))

    sk1_decryption_suite = AES.new(sk1_secret_key, AES.MODE_CFB, sk1_iv)
    auth_payload = sk1_decryption_suite.decrypt(authenticator).decode("utf-8")
    auth = json.loads(auth_payload)
    if tgt["username"] != auth["username"]:
        return jsonify({"status": "Invalid Authenticator!"}), 401

    auth_timestamp = datetime.strptime(auth.get("timestamp"), "%Y-%m-%d %H:%M:%S.%f")
    tgt_timestamp = datetime.strptime(tgt.get("timestamp"), "%Y-%m-%d %H:%M:%S.%f")
    if auth_timestamp - tgt_timestamp > timedelta(minutes=float(tgt["lifetime"])):
        return (
            jsonify({"status": "EXPIRED!!", "message": "Ticket Lifetime Expired!!"}),
            401,
        )

    sk2 = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    sk2 = sk2.encode("utf-8")
    new_iv = os.urandom(16)

    # prepare the service payload for client
    service_payload = {
        "user_id": str(auth.get("user_id")),
        "service_id": str(auth.get("server_id")),
        "timestamp": str(datetime.now()),
        "lifetime_of_ticket": "2",
        "SK2": sk2.decode("utf-8"),
        "iv": new_iv.hex(),
    }

    service_secret_key = b"secretkey1234567"
    initial_vector = os.urandom(16)

    # encrypt the service payload using service_secret_key
    service_enc_suite = AES.new(service_secret_key, AES.MODE_CFB, initial_vector)
    service_ticket_encrypted = service_enc_suite.encrypt(
        json.dumps(service_payload).encode("utf-8")
    )

    # prepare the tgs payload for client
    tgs_ack_payload = {
        "service_id": str(tgt.get("service_id")),
        "timestamp": str(datetime.now()),
        "lifetime_of_ticket": auth["lifetime_of_ticket"],
        "SK2": sk2.decode("utf-8"),
        "iv": new_iv.hex(),
    }

    # encrypt the tgs payload using sk1_secret_key
    tgs_encrypt_suite = AES.new(sk1_secret_key, AES.MODE_CFB, sk1_iv)
    tgs_ack_encrypted = tgs_encrypt_suite.encrypt(
        json.dumps(tgs_ack_payload).encode("utf-8")
    )

    print("TGS Ack and Service Ticket sent to client")
    return jsonify(
        {
            "status": "OK",
            "message": "Ticket Granted!",
            "tgs_ack_ticket": base64.b64encode(tgs_ack_encrypted).decode("utf-8"),
            "service_ticket": base64.b64encode(service_ticket_encrypted).decode(
                "utf-8"
            ),
        }
    )


if __name__ == "__main__":
    app.run(debug=True, port=8989)
