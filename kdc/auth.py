import os
import json
import secrets
import binascii
import base64
from flask import Flask, jsonify, request
from pymongo import MongoClient
from Crypto.Cipher import AES

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
client = MongoClient('mongodb://localhost:27017/')
db = client['cc']
user = db['user']
service = db['service']

user_secret_key = {}

@app.post('/kinit')
def user_secret_generation():
    pem_user_public_key = request.json.get('public_key')
    user_name = request.json.get('username')
    user_public_key = serialization.load_pem_public_key(pem_user_public_key.encode('utf-8'), backend=default_backend())
    
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    shared_secret = private_key.exchange(ec.ECDH(), user_public_key)
    
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    secret_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requires 32 bytes
        salt=None,
        info=None,
        backend=default_backend()
    ).derive(shared_secret)
    

    iv = os.urandom(16)
    
    if user.find_one({"username": user_name}):
        return {"status": "USER EXISTS", "message": "User already exists"}, 404
    user.insert_one({"username": user_name, "secret_key": secret_key, "iv": iv.hex()})
    
    payload = {"status": "OK", "public_key": pem_public_key.decode('utf-8'), 'iv': iv.hex()}
    return payload

@app.post('/user')
def create_user():
    user_name = request.json.get('username')
    user_data = user.find_one({"username": user_name})
    if not user_data:
        return jsonify({"status": "USER NOT EXISTS", "message": "User not created"}), 404
    
    secret_key = user_data.get('secret_key')
    iv = bytes.fromhex(user_data.get('iv'))

    encrypted_payload = base64.b64decode(request.json.get('payload'))
    encryption_suite = AES.new(secret_key, AES.MODE_CFB, iv)
    payload = encryption_suite.decrypt(encrypted_payload).decode('utf-8')
    payload = json.loads(payload)
    password = payload.get('password')
    user.update_one({"username": user_name}, {'$set': {"password": password}})
    return {"status": "OK", "message": "User created"}

if __name__ == '__main__':
    app.run(debug=True, port=6969)