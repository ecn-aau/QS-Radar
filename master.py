import requests
import base64
import urllib.parse
import oqs
import json

from Crypto.Cipher import AES


MASTER_KMS_HOST = "" # Address of KMS, maybe there is only one
MASTER_KMS_PORT = ""
MASTER_KMS_BASE_URL = f"https://{MASTER_KMS_HOST}:{MASTER_KMS_PORT}/api/v1" # KMS cert might be self-signed?
SLAVE_ID = ""
SLAVE_URL = ""
KEY_LENGTH = 256  # In bits
KEY_AMOUNT = 1
TIMEOUT = 10
VERIFY_SSL = True # If KMS cert is self-signed, set to False, but be aware
SIGALG = "ML-DSA-87"

# Unsure if needed, we will see at setup
# HEADERS = {
#     "Content-Type": "application/json",
#     "Authorization": f"Bearer {API_KEY}"
# }



def request_qkd_key() -> tuple[str, bytes]:
    get_key_url = f"{MASTER_KMS_BASE_URL}/keys/{urllib.parse.urlencode(SLAVE_ID)}/enc_keys"

    # Based on https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf Table 10
    payload = {
        "number": KEY_AMOUNT,
        "size": KEY_LENGTH,
    }

    try:
        response = requests.post(
            url = get_key_url,
            # headers = HEADERS,
            json = payload,
            timeout = TIMEOUT,
            verify = VERIFY_SSL
        )
        response.raise_for_status()

        key_info = response.json()

        # Right now, we consider only 1 key
        # Check for capital K, documentation might mislead
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
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
    }


def sign_data(encrypted_data: object, key_ID: str) -> object:
    with open("master_keys.json", "r") as file:
        data = json.load(file)
    private_key = data["private_key"]
    private_key = base64.b64decode(private_key)
    signer = oqs.Signature(SIGALG, private_key)

    encrypted_data["key_ID"] = key_ID
    signature = signer.sign(json.dumps(encrypt_data, sort_keys=True).encode())
    encrypted_data["signature"] = base64.b64encode(signature).decode('utf-8')

    return encrypted_data


def send_data(payload: object) -> None:
    try:
        response = requests.post(url=SLAVE_URL, json=payload, timeout=10)
        response.raise_for_status()
    except requests.exceptions.HTTPError as http_err:
        print(f'HTTP error occurred: {http_err} - Status Code: {response.status_code}')
    except requests.exceptions.ConnectionError as conn_err:
        print(f'Connection error occurred: {conn_err}')
    except requests.exceptions.Timeout as timeout_err:
        print(f'Timeout error occurred: {timeout_err}')
    except requests.exceptions.RequestException as req_err:
        print(f'Unexpected error: {req_err}')


def read_data() -> bytes:
    with open('data.bin', 'rb') as f:
        return f.read()


if __name__ == "__main__":
    data = read_data()
    key_ID, key = request_qkd_key()
    encrypted_data = encrypt_data(key, data)
    payload = sign_data(encrypted_data, key_ID)
    send_data(payload)
