import requests
import base64
import urllib.parse
import oqs
import json

from Crypto.Cipher import AES
from threading import Thread
from http.server import BaseHTTPRequestHandler, HTTPServer

SLAVE_KMS_HOST = "" # Address of KMS, maybe there is only one
SLAVE_KMS_PORT = ""
SLAVE_KMS_BASE_URL = f"https://{SLAVE_KMS_HOST}:{SLAVE_KMS_PORT}/api/v1" # KMS cert might be self-signed?
MASTER_ID = ""
TIMEOUT = 10
VERIFY_SSL = True # If KMS cert is self-signed, set to False, but be aware
ENCODING = "utf-8"
SIGALG = "ML-DSA-87"
LISTENING_URL = ""
LISTENING_PORT = ""

# Unsure if needed, we will see at setup
# HEADERS = {
#     "Content-Type": "application/json",
#     "Authorization": f"Bearer {API_KEY}"
# }

def request_qkd_key_with_ID(key_id: str) -> bytes:
    get_key_with_IDs_url = f"{SLAVE_KMS_BASE_URL}/keys/{urllib.parse.urlencode(MASTER_ID)}/dec_keys"

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
            # headers = HEADERS,
            json = payload,
            timeout = TIMEOUT,
            verify = VERIFY_SSL
        )
        response.raise_for_status()

        key_info = response.json()

        # Right now, we consider only 1 key
        # Check for capital K, documentation might mislead
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


def verify_signature(payload: object) -> bool:
    signature = base64.b64decode(payload["signature"])
    signed_data = {
        "nonce": payload["nonce"],
        "ciphertext": payload["ciphertext"],
        "tag": payload["ciphertext"],
        "key_ID": payload["key_ID"],
    }
    message = json.dumps(signed_data, sort_keys=True).encode(ENCODING)

    with open("master_keys.json", "r") as file:
        data = json.load(file)
    public_key = data["public_key"]
    public_key = base64.b64decode(public_key)

    with oqs.Signature(SIGALG) as verifier:
        return verifier.verify(message, signature, public_key)


def handle_request(payload) -> None:
    signature_valid = verify_signature(payload=payload)
    if not signature_valid:
        print('Invalid signature on payload! Tampering detected.')
        return
    key = request_qkd_key_with_ID(key_id=payload["key_ID"])
    data = decrypt_data(payload=payload, key=key)
    print(f'Data received: {data[:50].hex()}...')
    # Check if data is the same? In theory not necessary, at least don't measure the execution time for it


class SlaveHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        content_length = int(self.headers.get('Content-Length', 0))
        payload = self.rfile.read(content_length)

        try:
            data = json.loads(payload)
            print(f"Received JSON: {data}")
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON")
            return

        Thread(target=handle_request, args=(data,), daemon=True).start()

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Ok")

    def log_message(self, format, *args):
        # Disable default logging
        return


def run():
    server = HTTPServer((LISTENING_URL, LISTENING_PORT), SlaveHandler)
    print(f"Listening on http://{LISTENING_URL}:{LISTENING_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down...")
        server.server_close()


if __name__ == "__main__":
    run()
