import requests
import base64
import hashlib
import json
import logging
import socket

from Crypto.Cipher import AES
from flask import Flask, request, jsonify


CLIENT_B_KMS_HOST = "192.168.3.128" # Address of KMS, maybe there is only one
CLIENT_B_KMS_PORT = "8200"
CLIENT_B_KMS_BASE_URL = f"https://{CLIENT_B_KMS_HOST}:{CLIENT_B_KMS_PORT}/api/v1" # KMS cert might be self-signed?
CLIENT_A_ID = "Alice254250"


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
        print(f'HTTP error occurred: {http_err} - Status Code: {response.status_code}')
    except requests.exceptions.ConnectionError as conn_err:
        print(f'Connection error occurred: {conn_err}')
    except requests.exceptions.Timeout as timeout_err:
        print(f'Timeout error occurred: {timeout_err}')
    except requests.exceptions.RequestException as err:
        print(f"Request failed: {err}")


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


def send_data(payload: bytes) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDP_IP = "127.0.0.1"
    UDP_PORT = 56002

    hash = hashlib.sha256(payload).hexdigest()

    sock.sendto(payload, (UDP_IP, UDP_PORT))
    print(f"Packet forwarded: SHA-256 {hash}")


app = Flask(__name__)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

@app.route('/', methods=['POST'])
def handle_post():
    payload = request.data
    
    try:
        payload = json.loads(payload)    
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON'}), 400

    hash = hashlib.sha256(request.data).hexdigest()
    print(f"Encrypted data received: SHA-256 {hash}")
    key = request_qkd_key_with_ID(key_id=payload["key_ID"])
    raw_data = decrypt_data(payload=payload, key=key)
    send_data(payload=raw_data)
    
    return jsonify({'status': 'success'}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
