import requests
import base64
import oqs
import json
import time

from Crypto.Cipher import AES
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

CLIENT_B_KMS_HOST = "192.168.3.128" # Address of KMS, maybe there is only one
CLIENT_B_KMS_PORT = "8200"
CLIENT_B_KMS_BASE_URL = f"https://{CLIENT_B_KMS_HOST}:{CLIENT_B_KMS_PORT}/api/v1" # KMS cert might be self-signed?
CLIENT_A_ID = "Alice254250"
SIGALG = "ML-DSA-87"
LISTENING_URL = "localhost"
LISTENING_PORT = 8080
NANO_TO_MILLI = 100000
MAX_REQUESTS = 100000

lock = threading.Lock()
outputs = []
request_count = 1 

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


def get_public_key() -> bytes:
    with open("../keys/clientA_keys.json", "r") as file:
        data = json.load(file)
    public_key = data["public_key"]
    return base64.b64decode(public_key)


class CLIENTBHandler(BaseHTTPRequestHandler):
    def __init__(self, paramters):
        self.pub_key = get_public_key()

    def do_POST(self) -> None:
        content_length = int(self.headers.get('Content-Length', 0))
        payload = self.rfile.read(content_length)

        try:
            data = json.loads(payload)
            # print(f"Received JSON: {data}")
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON")
            return

        threading.Thread(target=self.handle_request, args=(data,), daemon=True).start()

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Ok")

    def log_message(self, format, *args):
        # Disable default logging
        return
    
    def handle_request(self, payload) -> None:
        time_start = time.perf_counter_ns()
        signature_valid = verify_signature(payload=payload, public_key=self.pub_key)
        time_signature_verification = time.perf_counter_ns()
        if not signature_valid:
            print('Invalid signature on payload! Tampering detected.')
            return

        key = request_qkd_key_with_ID(key_id=payload["key_ID"])
        time_qkd_key = time.perf_counter_ns()

        data = decrypt_data(payload=payload, key=key)
        time_decrypt = time.perf_counter_ns()

        # Execution ID (request_count), elapsed signature verification, elapsed qkd key retrieval, elapsed decryption, elapsed request handling
        output = f"{request_count},{(time_signature_verification - time_start) / NANO_TO_MILLI},{(time_qkd_key - time_signature_verification) / NANO_TO_MILLI},{(time_decrypt - time_qkd_key) / NANO_TO_MILLI},{(time_decrypt - time_start) / NANO_TO_MILLI}"

        with lock:
            global request_count
            request_count += 1
            
            outputs.append(output)

            if (request_count > MAX_REQUESTS):
                self.server.shutdown()


def run():
    server = HTTPServer((LISTENING_URL, LISTENING_PORT), CLIENTBHandler)
    print(f"Listening on http://{LISTENING_URL}:{LISTENING_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down...")
        server.server_close()
    
    with open("../out/output_clientB.txt", "w") as output:
        for op in outputs:
            output.write(op)


if __name__ == "__main__":
    run()
