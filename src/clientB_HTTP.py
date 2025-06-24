import requests
import base64
import hashlib
import json
import logging
import socket
import time
import oqs

from Crypto.Cipher import AES
from flask import Flask, request, jsonify


CLIENT_B_KMS_HOST = "192.168.3.128" # Address of KMS, maybe there is only one
CLIENT_B_KMS_PORT = "8200"
CLIENT_B_KMS_BASE_URL = f"https://{CLIENT_B_KMS_HOST}:{CLIENT_B_KMS_PORT}/api/v1" # KMS cert might be self-signed?
CLIENT_A_ID = "Alice254250"
SIGALG = "ML-DSA-87"

logging.basicConfig(filename="logB.log", level=logging.INFO)

def request_qkd_key_with_ID(key_id: str) -> bytes:
    get_key_with_IDs_url = f"{CLIENT_B_KMS_BASE_URL}/keys/{CLIENT_A_ID}/dec_keys"

    # Based on https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf Table 12
    payload = {
        "key_IDs": [
            {
                "key_ID": key_id,
            }
        ],
    }

    try:
        response = requests.post(
            url = get_key_with_IDs_url,
            json = payload,
            verify = 'ca-cert.crt'
        )
        response.raise_for_status()

        key_info = response.json()
        return base64.b64decode(key_info['Keys'][0]['key'])

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err} - Status Code: {response.status_code}")
        logging.ERROR(str(time.time())+f": HTTP error occurred: {http_err} - Status Code: {response.status_code}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
        logging.ERROR(str(time.time())+f": Connection error occurred: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")
        logging.ERROR(str(time.time())+f": Timeout error occurred: {timeout_err}")
    except requests.exceptions.RequestException as err:
        print(f"Request failed: {err}")
        logging.ERROR(str(time.time())+f": Request failed: {err}")


def decrypt_data(payload: object, key: bytes) -> bytes:
    nonce = base64.b64decode(payload["nonce"])
    tag = base64.b64decode(payload["tag"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        message = cipher.decrypt_and_verify(ciphertext, tag)
        return message

    except ValueError:
        print("Decryption failed or data tampered")
        logging.ERROR(str(time.time())+": Decryption failed or data tampered")


def send_data(payload: bytes) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDP_IP = "127.0.0.1"
    UDP_PORT = 56002

    hash = hashlib.sha256(payload).hexdigest()

    sock.sendto(payload, (UDP_IP, UDP_PORT))
    print(f"Packet forwarded: SHA-256 {hash}")
    logging.INFO(str(time.time())+f": Packet forwarded: SHA-256 {hash}")


def verify_signature(payload: object, public_key: bytes) -> bool:
    signature = base64.b64decode(payload["signature"])
    signed_data = {
        "nonce": payload["nonce"],
        "ciphertext": payload["ciphertext"],
        "tag": payload["tag"],
        "key_ID": payload["key_ID"],
    }
    message = json.dumps(signed_data, sort_keys=True).encode()

    with oqs.Signature(SIGALG) as verifier:
        return verifier.verify(message, signature, public_key)

def get_public_key() -> bytes:
    with open("../keys/ppk.json", "r") as file:
        data = json.load(file)
    public_key = data["public_key"]
    return base64.b64decode(public_key)

app = Flask(__name__)

@app.route('/', methods=['POST'])
def handle_post():
    payload = request.data
    
    try:
        payload = json.loads(payload)    
    except json.JSONDecodeError:
        logging.ERROR(str(time.time())+": Invalid JSON")
        return jsonify({'error': 'Invalid JSON'}), 400

    hash = hashlib.sha256(request.data).hexdigest()
    print(f"Encrypted data received: SHA-256 {hash}")
    logging.INFO(f": Encrypted data received: SHA-256 {hash}")

    if verify_signature(payload, get_public_key()):
        key = request_qkd_key_with_ID(key_id=payload["key_ID"])
        raw_data = decrypt_data(payload=payload, key=key)
        send_data(payload=raw_data)
    else:
        logging.ERROR(str(time.time())+": Invalid signature")
        return jsonify({'error': 'Invalid signature'}), 400

    return jsonify({'status': 'success'}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
