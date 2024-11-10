import json
import base64
import socket
import requests
from time import sleep
from Crypto.Cipher import AES
from datetime import datetime
import traceback
from termcolor import colored
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def decrypt_data(key: str, data: bytes, iv: bytes):
    """
    Decrypts encrypted data using AES with the derived key.
    """
    secret_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend(),
    ).derive(key.encode("utf-8"))

    decryption_suite = AES.new(secret_key, AES.MODE_CFB, iv)
    encrypted_data = base64.b64decode(data)
    payload = decryption_suite.decrypt(encrypted_data).decode("utf-8")
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return payload


def encrypt_data(key: str, data: dict | str, iv: bytes):
    """
    Encrypts data using AES with the derived key.
    """
    secret_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend(),
    ).derive(key.encode("utf-8"))

    if isinstance(data, dict):
        data = json.dumps(data)
    data = data.encode("utf-8")

    encrypt_suite = AES.new(secret_key, AES.MODE_CFB, iv)
    encrypted_data = encrypt_suite.encrypt(data)
    payload = base64.b64encode(encrypted_data).decode("utf-8")
    return payload


def request_as(user_name, password, iv):
    """
    Phase 1: Contact the Authentication Server to obtain a ticket-granting ticket (TGT).
    """
    print(
        colored(
            "=== Phase 1: Requesting Authentication Server ===", "blue", attrs=["bold"]
        )
    )
    network_address = socket.gethostbyname(socket.gethostname())
    payload = {
        "username": user_name,
        "service_id": "tgs",
        "nw_addr": str(network_address),
        "lifetime_of_tgt": "2",
    }
    print(colored("Payload: ", attrs=["bold"]))
    print(json.dumps(payload, indent=2))
    print()
    print("Encrypting payload with user's password...")
    encrypted_payload = encrypt_data(password, payload, iv)
    print(colored("Encrypted Payload:", attrs=["bold"]), encrypted_payload)
    print()

    request_data = {
        "username": user_name,
        "payload": encrypted_payload,
    }
    response = requests.post("http://localhost:6969/authenticate", json=request_data)
    print(
        "Requesting Authenticating Server with the following payload:",
        json.dumps(request_data, indent=2),
    )

    if response.status_code != 200:
        print(colored("User Authentication Failed!", "red"))
        raise Exception("User Authentication Failed!")

    print(colored("Successfully Authenticated. Ticket Received from AS.", "green"))
    return response.json()


def request_tgs(as_response, user_name, password, iv):
    """
    Phase 2: Requesting Ticket Granting Server for access to a specific service.
    """
    print(
        colored(
            "=== Phase 2: Requesting Ticket Granting Server (TGS) ===",
            "blue",
            attrs=["bold"],
        )
    )
    ack = as_response.get("ack")
    tgt = as_response.get("tgt")
    print("\nResponse from AS:", json.dumps(as_response, indent=2))

    # Decrypt the acknowledgment payload to retrieve the session key (SK1)
    print("\nDecrypting acknowledgment payload using users password...")
    ack_payload = decrypt_data(password, ack, iv)
    sk1 = ack_payload.get("SK1")
    iv = bytes.fromhex(ack_payload.get("iv"))

    print(colored("Acknowledgment from AS:", "yellow"))
    print(json.dumps(ack_payload, indent=2))

    print(colored("\nTicket Granting Ticket (TGT) received from AS:", "yellow"))
    print(tgt)
    print("-" * 50)

    # Prepare the TGS request payload
    service_id = input("Enter Service ID for access: ")
    tgs_request_payload = {
        "service_id": service_id,
        "lifetime_of_ticket": "2",
        "username": user_name,
        "timestamp": str(datetime.now()),
    }

    print("\nAuthenticator Request Payload:")
    print(json.dumps(tgs_request_payload, indent=2))

    encrypted_authenticator = encrypt_data(sk1, tgs_request_payload, iv)
    print("\nEncrypted Authenticator:", encrypted_authenticator)

    request_data = {
        "username": user_name,
        "authenticator": encrypted_authenticator,
        "ticket_granting_ticket": tgt,
    }
    print(
        "\nRequesting TGS with the following payload:",
        json.dumps(request_data, indent=2),
    )

    response = requests.post("http://localhost:8989/tickets", json=request_data)

    if response.status_code == 401:
        error_status = response.json().get("status")
        print(colored("Error: " + error_status, "red"))
        return

    if response.status_code != 200:
        print(colored("Failed to contact TGS!", "red"))
        raise Exception("TGS contact failed!")

    print(colored("\nTicket Granted by TGS!", "green"))
    tgs_response = response.json()
    print(colored("\nService Ticket Payload from TGS:", "yellow"))
    print(json.dumps(tgs_response, indent=2))

    decrypted_service_payload = decrypt_data(
        sk1, tgs_response.get("tgs_ack_ticket"), iv
    )
    print(colored("\nDecrypted TGS ACK Payload:", "yellow"))
    print(json.dumps(decrypted_service_payload, indent=2))
    print("-" * 50)


def main():
    try:
        print(colored("Starting Secure Client Authentication", "green", attrs=["bold"]))

        with open("response.json", "r") as f:
            response_json = json.load(f)

        user_name = response_json.get("username")
        iv = bytes.fromhex(response_json.get("iv"))
        password = response_json.get("password")

        print(colored("Authenticating with the Authentication Server...", "cyan"))
        as_response = request_as(user_name, password, iv)

        print(colored("\nProceeding to request TGS for service access...", "cyan"))
        request_tgs(as_response, user_name, password, iv)
    except Exception as e:
        print(colored("An error occurred:", "red"))
        print(e)
        traceback.print_exc()


if __name__ == "__main__":
    main()
