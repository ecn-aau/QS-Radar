import requests
import base64
import oqs
import json
import time

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


def sign_data(encrypted_data: object, key_id: str) -> object:
    with open("../keys/clientA_keys.json", "r") as file:
        data = json.load(file)
    private_key = data["private_key"]
    private_key = base64.b64decode(private_key)
    signer = oqs.Signature(SIGALG, private_key)

    encrypted_data["key_ID"] = key_id
    signature = signer.sign(json.dumps(encrypted_data, sort_keys=True).encode())
    encrypted_data["signature"] = base64.b64encode(signature).decode()

    return encrypted_data


def send_data(payload: object) -> None:
    try:
        response = requests.post(url=CLIENT_B_URL, json=payload, timeout=10)
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
    with open('../data/data.bin', 'rb') as f:
        return f.read()

outputs = []

if __name__ == "__main__":
    data = read_data()
    
    for i in range(EXECUTION_AMOUNT):
        # time_start = time.perf_counter_ns()

        key_ID, key = request_qkd_key()
        # time_qkd_key = time.perf_counter_ns()

        encrypted_data = encrypt_data(data=data, key=key)
        # time_encryption = time.perf_counter_ns()

        payload = sign_data(encrypted_data=encrypted_data, key_id=key_ID)
        # print(payload)
        # time_sign = time.perf_counter_ns()

        send_data(payload=payload)
        # time_data_transfer = time.perf_counter_ns()
        # Execution id, elapsed qkd key generation, elapsed encryption, elapsed signature generation, elapsed transmitting data, elapsed all time, end time
        # measured_output = f"{i+1},{(time_qkd_key - time_start) / NANO_TO_MILLI},{(time_encryption - time_qkd_key) / NANO_TO_MILLI},{(time_sign - time_encryption) / NANO_TO_MILLI},{(time_data_transfer - time_sign) / NANO_TO_MILLI},{(time_data_transfer - time_start) / NANO_TO_MILLI},{time_data_transfer}\n"
        # outputs.append(measured_output)
        



    # print(f"ID: {key_ID}\nKey: {key.hex()}")
    # print(f"Encrypted data: {encrypted_data}")
    # print(f"Payload: {payload}")
    
    # with open("../out/output_clientA.txt", "w") as output:
      #  for op in outputs:
       #     output.write(op)
