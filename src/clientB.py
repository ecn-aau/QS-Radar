import requests
import base64
import hashlib
import json
import logging
import socket
import oqs

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256, SHAKE128
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.DH import key_agreement as ECDH
from flask import Flask, request, jsonify


CLIENT_B_KMS_HOST = "192.168.3.128" # Address of KMS, maybe there is only one
CLIENT_B_KMS_PORT = "8200"
CLIENT_B_KMS_BASE_URL = f"https://{CLIENT_B_KMS_HOST}:{CLIENT_B_KMS_PORT}/api/v1" # KMS cert might be self-signed?
CLIENT_A_ID = "Alice254250"
KEY_EXCHANGE = "BB84" # Options: ECDH, BB84, ML_KEM-512, ML-KEM-768, ML-KEM-1024
SIGALG = "ML-DSA-87" # Options: RSA, ML-DSA-44, ML-DSA-65, ML-DSA-87

logging.basicConfig(
    filename="logB.log",
    format="%(asctime)s.%(msecs)03d::%(levelname)s::%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.DEBUG,
    filemode="x")


def kdf(x):
    return SHAKE128.new(x).read(32)


def request_qkd_key_with_ID(key_ID: str) -> bytes:
    get_key_with_IDs_url = f"{CLIENT_B_KMS_BASE_URL}/keys/{CLIENT_A_ID}/dec_keys"

    # Based on https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf Table 12
    payload = {
        "key_IDs": [
            {
                "key_ID": key_ID,
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
        logging.error(f"HTTP error occurred: {http_err} - Status Code: {response.status_code}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
        logging.error(f"Connection error occurred: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")
        logging.error(f"Timeout error occurred: {timeout_err}")
    except requests.exceptions.RequestException as err:
        print(f"Request failed: {err}")
        logging.error(f"Request failed: {err}")


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
        logging.error("Decryption failed or data tampered")


def send_data(payload: bytes) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDP_IP = "127.0.0.1"
    UDP_PORT = 56002

    sock.sendto(payload, (UDP_IP, UDP_PORT))


def verify_signature(payload: object, public_key: bytes) -> bool:
    signature = base64.b64decode(payload["signature"])
    signed_data = {
        "nonce": payload["nonce"],
        "ciphertext": payload["ciphertext"],
        "tag": payload["tag"],
        "key_ID": payload["key_ID"],
    }
    message = json.dumps(signed_data, sort_keys=True).encode()

    if SIGALG == "RSA":
        hash = SHA256.new(message)
        rsa_key = RSA.import_key(public_key)
        try:
            pkcs1_15.new(rsa_key).verify(hash, signature)
            return True
        except (ValueError, TypeError):
            return False
    else:
        with oqs.Signature(SIGALG) as verifier:
            return verifier.verify(message, signature, public_key)


def get_public_key() -> bytes:
    with open("../keys/ppk-"+SIGALG+".json", "r") as file:
        data = json.load(file)
    public_key = data["public_key"]
    return base64.b64decode(public_key)


app = Flask(__name__)
app.secret_key = bytearray(32) # WARNING: Not the intended use of this variable (development only)

@app.route('/data', methods=['POST'])
def handle_data():
    payload = request.data
    try:
        payload = json.loads(payload)
    except json.JSONDecodeError:
        logging.error("Invalid JSON")
        return jsonify({'error': 'Invalid JSON'}), 400

    hash = hashlib.sha256(request.data).hexdigest()
    print(f"Encrypted and signed payload received: SHA-256 {hash}")
    logging.info(f"Encrypted and signed payload received: SHA-256 {hash}")

    if verify_signature(payload, get_public_key()):
        logging.debug(f"Verified signature: {SIGALG}")

        if KEY_EXCHANGE == "BB84":
            key = request_qkd_key_with_ID(key_ID=payload['key_ID'])
        else:
            key = app.secret_key
            app.secret_key = bytearray(32)
        logging.debug(f"{KEY_EXCHANGE} key collected: ID {payload['key_ID']}")

        raw_data = decrypt_data(payload=payload, key=key)
        logging.debug(f"Decrypted data with key: ID {payload['key_ID']}")

        send_data(payload=raw_data)
        print(f"Raw packet forwarded: SHA-256 {hash}")
        logging.info(f"Raw packet forwarded: SHA-256 {hash}")
    else:
        logging.error(f"Invalid signature: {SIGALG}")
        return jsonify({'error': 'Invalid signature'}), 400

    return jsonify({'status': 'success'}), 200

@app.route('/kem', methods=['POST'])
def handle_kem():
    payload = request.data
    try:
        payload = json.loads(payload)
    except json.JSONDecodeError:
        logging.error("Invalid JSON")
        return jsonify({'error': 'Invalid JSON'}), 400

    logging.debug(f"Received KEM request: ID {payload['key_ID']}")

    if KEY_EXCHANGE == "ECDH":
        KEM_pv_key = ECC.generate(curve='p256')
        KEM_pb_key = ECC.import_key(payload['public_key'])
        shared_secret = ECDH(eph_priv=KEM_pv_key, eph_pub=KEM_pb_key, kdf=kdf)
        app.secret_key = shared_secret
        return jsonify({'status': 'success', 'public_key': KEM_pv_key.public_key().export_key()}), 200
    else:
        with oqs.KeyEncapsulation(KEY_EXCHANGE) as server:
            KEM_pb_key = base64.b64decode(payload['public_key'])
            ciphertext, shared_secret = server.encap_secret(KEM_pb_key)
        app.secret_key = shared_secret
        return jsonify({'status': 'success', 'ciphertext': base64.b64encode(ciphertext).decode()}), 200

if __name__ == '__main__':
    logging.info(f"Starting QS-Radar-C2: {SIGALG} + {KEY_EXCHANGE}")
    app.run(host='0.0.0.0', port=8080)
