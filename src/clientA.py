import requests
import base64
import hashlib
import json
import socket
import logging
import oqs

from random import randbytes
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256, SHAKE128
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.DH import key_agreement as ECDH

CLIENT_A_KMS_HOST = "192.168.3.126" # Address of KMS, maybe there is only one
CLIENT_A_KMS_PORT = "8200"
CLIENT_A_KMS_BASE_URL = f"https://{CLIENT_A_KMS_HOST}:{CLIENT_A_KMS_PORT}/api/v1" # KMS cert might be self-signed?
CLIENT_B_ID = "Bob254250"
KEY_EXCHANGE = "BB84" # Options: ECDH, BB84, ML-KEM-512, ML-KEM-768, ML-DSA-1024
KEY_LENGTH = 256  # In bits
KEY_AMOUNT = 1
SIGALG = "ML-DSA-87" # Options: RSA, ML-DSA-44, ML-DSA-65, ML-DSA-87

logging.basicConfig(
    filename="logA.log",
    format="%(asctime)s.%(msecs)03d::%(levelname)s::%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.DEBUG,
    filemode="x")


def kdf(x):
    return SHAKE128.new(x).read(32)


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


def request_pqc_key() -> tuple[str, bytes]:
    with oqs.KeyEncapsulation(KEY_EXCHANGE) as client:
        KEM_pb_key = client.generate_keypair()

        payload = {
            "key_ID": base64.b64encode(randbytes(3)).decode(),
            "public_key": base64.b64encode(KEM_pb_key).decode(),
        }

        response = requests.post(url="http://192.168.3.102:8080/kem", json=payload, timeout=10)
        response.raise_for_status()
        shared_secret = client.decap_secret(base64.b64decode(response.json()['ciphertext']))

        return payload['key_ID'], shared_secret


def request_ecdh_key() -> tuple[str, bytes]:
    KEM_pv_key = ECC.generate(curve='p256')

    payload = {
        "key_ID": base64.b64encode(randbytes(3)).decode(),
        "public_key": KEM_pv_key.public_key().export_key(format='PEM'),
    }

    response = requests.post(url="http://192.168.3.102:8080/kem", json=payload, timeout=10)
    response.raise_for_status()
    KEM_pb_key = ECC.import_key(response.json()['public_key'])
    shared_secret = ECDH(eph_priv=KEM_pv_key, eph_pub=KEM_pb_key, kdf=kdf)

    return payload['key_ID'], shared_secret


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
        response = requests.post(url="http://192.168.3.102:8080/data", json=payload, timeout=10)
        response.raise_for_status()
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err} - Status Code: {response.status_code}")
        logging.error(f"HTTP error occurred: {http_err} - Status Code: {response.status_code}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
        logging.error(f"Connection error occurred: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")
        logging.error(f"Timeout error occurred: {timeout_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"Unexpected error: {req_err}")
        logging.error(f"Unexpected error: {req_err}")

def get_private_key() -> bytes:
    with open("../keys/ppk-"+SIGALG+".json", "r") as file:
        data = json.load(file)
    private_key = data["private_key"]
    return base64.b64decode(private_key)


def sign_data_pqc(encrypted_data: object, private_key: bytes) -> object:
    signer = oqs.Signature(SIGALG, private_key)
    signature = signer.sign(json.dumps(encrypted_data, sort_keys=True).encode())
    encrypted_data["signature"] = base64.b64encode(signature).decode()
    return encrypted_data


def sign_data_rsa(encrypted_data: object, private_key: bytes) -> object:
    hash = SHA256.new(json.dumps(encrypted_data, sort_keys=True).encode())
    rsa_key = RSA.import_key(private_key)
    signature = pkcs1_15.new(rsa_key).sign(hash)
    encrypted_data["signature"] = base64.b64encode(signature).decode()
    return encrypted_data


if __name__ == "__main__":
    logging.info(f"Starting QS-Radar: {SIGALG} + {KEY_EXCHANGE}")

    # Launch parameters
    UDP_IP = "127.0.0.1"
    UDP_PORT = 56000
    max_tx = 10 ** 5

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"Listening for UDP packets on: {UDP_IP}:{UDP_PORT}")
    logging.info(f"Listening for UDP packets on: {UDP_IP}:{UDP_PORT}")

    pv_key = get_private_key()
    logging.debug("Private key loaded successfully")

    tx_count = 0
    while tx_count < max_tx:
        tx_count += 1
        print(f"TX: {tx_count}")
        logging.info(f"TX count: {tx_count}")

        try:
            data, addr = sock.recvfrom(65535)

            hash = hashlib.sha256(data).hexdigest()
            print(f"Raw packet received: SHA-256 {hash}")
            logging.info(f"Raw packet received: SHA-256 {hash}")

            if KEY_EXCHANGE == "BB84":
                logging.debug("QKD key request initiated")
                key_ID, key = request_qkd_key()
                logging.debug(f"QKD key collected: size {KEY_LENGTH}, ID {key_ID}")
            elif KEY_EXCHANGE == "ECDH":
                logging.debug("Classical key request initiated")
                key_ID, key = request_ecdh_key()
                logging.debug(f"Classical key collected: ID {key_ID}")
            else:
                logging.debug("PQC key request initiated")
                key_ID, key = request_pqc_key()
                logging.debug(f"PQC key collected: ID {key_ID}")

            encrypted_data = encrypt_data(data=data, key=key)
            encrypted_data["key_ID"] = key_ID
            logging.debug(f"Encrypted data with key: ID {key_ID}")

            if SIGALG == "RSA":
                payload = sign_data_rsa(encrypted_data=encrypted_data, private_key=pv_key)
            else:
                payload = sign_data_pqc(encrypted_data=encrypted_data, private_key=pv_key)
            logging.debug(f"Signed data with private key: {SIGALG}")

            send_data(payload=payload)
            print(f"Encrypted and signed payload forwarded: SHA-256 {hash}")
            logging.info(f"Encrypted and signed payload forwarded: SHA-256 {hash}")
        except Exception as e:
            logging.error(e)
            logging.warning("Skipping this payload due to error")
            continue

    logging.info(f"Ending QS-Radar: {SIGALG} + {KEY_EXCHANGE}")