import requests
import base64
import oqs
import hashlib
import json
import socket

from Crypto.Cipher import AES


CLIENT_A_KMS_HOST = "192.168.3.126" # Address of KMS, maybe there is only one
CLIENT_A_KMS_PORT = "8200"
CLIENT_A_KMS_BASE_URL = f"https://{CLIENT_A_KMS_HOST}:{CLIENT_A_KMS_PORT}/api/v1" # KMS cert might be self-signed?
CLIENT_B_ID = "Bob254250"
CLIENT_B_HOST = "localhost"
CLIENT_B_PORT = 8080
CLIENT_B_URL = f"http://{CLIENT_B_HOST}:{CLIENT_B_PORT}"
KEY_LENGTH = 256  # In bits
KEY_AMOUNT = 1
TIMEOUT = 10
SIGALG = "ML-DSA-87"
EXECUTION_AMOUNT = 100000
NANO_TO_MILLI = 100000
UDP_LIMIT = 9216 # OS/hardware limit in bytes for max sendable UDP packet size. 9216 on macOS


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


def sign_data(encrypted_data: object, key_id: str, private_key: bytes) -> object:
    signer = oqs.Signature(SIGALG, private_key)
    encrypted_data["key_ID"] = key_id
    signature = signer.sign(json.dumps(encrypted_data, sort_keys=True).encode())
    encrypted_data["signature"] = base64.b64encode(signature).decode()
    return encrypted_data


def send_data(payload: bytes) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDP_IP = "127.0.0.1"
    UDP_PORT = 56001
    hash = hashlib.sha256(payload).hexdigest()

    sock.sendto(payload, (UDP_IP, UDP_PORT))
    print(f"Encrypted data forwarded: SHA-256 {hash}")


def get_private_key() -> bytes:
    with open("../keys/clientA_keys.json", "r") as file:
        data = json.load(file)
    private_key = data["private_key"]
    return base64.b64decode(private_key)


if __name__ == "__main__":
    priv_key = get_private_key()

    UDP_IP = "127.0.0.1"
    UDP_PORT = 56000

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"Listening for UDP packets on: {UDP_IP}:{UDP_PORT}")

    lost_keys = 0

    while True:
        data, addr = sock.recvfrom(UDP_LIMIT)
        hash = hashlib.sha256(data).hexdigest()
        print(f"Raw packet received: SHA-256 {hash}")
    
        key_ID, key = request_qkd_key()
        encrypted_data = encrypt_data(data=data, key=key)
        payload = sign_data(encrypted_data=encrypted_data, key_id=key_ID, private_key=priv_key)

        payload = json.dumps(payload).encode()
        if len(payload) > UDP_LIMIT:
            print(f"Payload too large, being discarded")
            print(f"Payload size: {len(payload)}")
            print(f"Message hash: SHA-256 {hash}")
            lost_keys += 1
            print(f"Lost keys because of too large messages: {lost_keys}")
        else:
            send_data(payload=payload)
