import requests
import base64
import hashlib
import json
import socket

from Crypto.Cipher import AES


CLIENT_A_KMS_HOST = "192.168.3.126" # Address of KMS, maybe there is only one
CLIENT_A_KMS_PORT = "8200"
CLIENT_A_KMS_BASE_URL = f"https://{CLIENT_A_KMS_HOST}:{CLIENT_A_KMS_PORT}/api/v1" # KMS cert might be self-signed?
CLIENT_B_ID = "Bob254250"
KEY_LENGTH = 256  # In bits
KEY_AMOUNT = 1


def request_qkd_key() -> tuple[str, bytes]:
    get_key_url = f"{CLIENT_A_KMS_BASE_URL}/keys/{CLIENT_B_ID}/enc_keys"

    # Based on https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf Table 10
    payload = {
        "number": KEY_AMOUNT,
        "size": KEY_LENGTH,
    }

    try:
        response = requests.post(
            url = get_key_url,
            json = payload,
            verify = 'ca-cert.crt'
        )
        response.raise_for_status()

        key_info = response.json()

        key_ID = key_info['Keys'][0]['key_ID']
        key = base64.b64decode(key_info['Keys'][0]['key'])
        return (key_ID, key)

    except requests.exceptions.HTTPError as http_err:
        print(f'HTTP error occurred: {http_err} - Status Code: {response.status_code}')
    except requests.exceptions.ConnectionError as conn_err:
        print(f'Connection error occurred: {conn_err}')
    except requests.exceptions.Timeout as timeout_err:
        print(f'Timeout error occurred: {timeout_err}')
    except requests.exceptions.RequestException as err:
        print(f"Request failed: {err}")


def encrypt_data(data: bytes, key: bytes) -> object:
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def send_data(payload) -> None:
    try:
        hash = hashlib.sha256(json.dumps(payload).encode()).hexdigest()
        response = requests.post(url="http://192.168.3.102:8080", json=payload, timeout=10)
        response.raise_for_status()
        print(f"Encrypted data forwarded: SHA-256 {hash}")
    except requests.exceptions.HTTPError as http_err:
        print(f'HTTP error occurred: {http_err} - Status Code: {response.status_code}')
    except requests.exceptions.ConnectionError as conn_err:
        print(f'Connection error occurred: {conn_err}')
    except requests.exceptions.Timeout as timeout_err:
        print(f'Timeout error occurred: {timeout_err}')
    except requests.exceptions.RequestException as req_err:
        print(f'Unexpected error: {req_err}')
    

if __name__ == "__main__":
    UDP_IP = "127.0.0.1"
    UDP_PORT = 56000

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"Listening for UDP packets on: {UDP_IP}:{UDP_PORT}")

    lost_keys = 0

    while True:
        data, addr = sock.recvfrom(65535)
        hash = hashlib.sha256(data).hexdigest()
        print(f"Raw packet received: SHA-256 {hash}")
    
        key_ID, key = request_qkd_key()
        encrypted_data = encrypt_data(data=data, key=key)
        encrypted_data["key_ID"] = key_ID
        payload = encrypted_data
        send_data(payload=payload)
