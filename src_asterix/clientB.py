import requests
import base64
import oqs
import hashlib
import json
import socket

from Crypto.Cipher import AES


CLIENT_B_KMS_HOST = "192.168.3.128" # Address of KMS, maybe there is only one
CLIENT_B_KMS_PORT = "8200"
CLIENT_B_KMS_BASE_URL = f"https://{CLIENT_B_KMS_HOST}:{CLIENT_B_KMS_PORT}/api/v1" # KMS cert might be self-signed?
CLIENT_A_ID = "Alice254250"
SIGALG = "ML-DSA-87"
LISTENING_URL = "localhost"
LISTENING_PORT = 8080
NANO_TO_MILLI = 100000
MAX_REQUESTS = 100000
UDP_LIMIT = 9216 # OS/hardware limit in bytes for max sendable UDP packet size. 9216 on macOS


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

def send_data(payload: bytes) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDP_IP = "127.0.0.1"
    UDP_PORT = 56002

    hash = hashlib.sha256(payload).hexdigest()

    sock.sendto(payload, (UDP_IP, UDP_PORT))
    print(f"Packet forwarded: SHA-256 {hash}")


def get_public_key() -> bytes:
    with open("../keys/clientA_keys.json", "r") as file:
        data = json.load(file)
    public_key = data["public_key"]
    return base64.b64decode(public_key)


if __name__ == "__main__":
    pub_key = get_public_key()

    UDP_IP = "127.0.0.1"
    UDP_PORT = 56001

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"Listening for UDP packets on: {UDP_IP}:{UDP_PORT}")

    while True:
        data, addr = sock.recvfrom(UDP_LIMIT)
        hash = hashlib.sha256(data).hexdigest()
        print(f"Encrypted data received: SHA-256 {hash}")

        try:
            decoded_data = data.decode()
            payload = json.loads(decoded_data)
            if verify_signature(payload=payload, public_key=pub_key):
                # If signature is good, we continue
                key = request_qkd_key_with_ID(key_id=payload["key_ID"])
                raw_data = decrypt_data(payload=payload, key=key)
                send_data(payload=raw_data)
            else:
                # If signature is not good, we drop packet and log
                print(f"Wrong signature, packet was dropped: SHA-256 {hash}")
        except:
            print(f"JSON EXCEPTION: {decoded_data}")
