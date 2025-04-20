import requests
import base64

MASTER_KMS_HOST = "" # Address of KMS
MASTER_KMS_PORT = ""
MASTER_KMS_BASE_URL = f"https://{MASTER_KMS_HOST}:{MASTER_KMS_PORT}/api/v1" # KMS cert might be self-signed?
SLAVE_ID = ""
KEY_LENGTH = 256  # In bits
KEY_AMOUNT = 1
TIMEOUT = 10
VERIFY_SSL = True # If KMS cert is self-signed, set to False, but be aware

# Unsure if needed, we will see at setup
# HEADERS = {
#     "Content-Type": "application/json",
#     "Authorization": f"Bearer {API_KEY}"
# }

def request_qkd_key() -> None:
    get_key_url = f"{MASTER_KMS_BASE_URL}/keys/{SLAVE_ID}/enc_keys"

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

        # Check for capital K, documentation might mislead
        for key_item in key_info["Keys"]:
            key_ID = key_item['key_ID']
            key = key_item['key']
            print("------- 🔐 QKD Key Received -------")
            print(f"Key ID: {key_ID}")
            print(f"Key in base64: {key}\n")
            print(f"Key in hex: {base64.b64decode(key).hex()}")

    except requests.exceptions.RequestException as err:
        print(f"❌ Request failed: {err}")

if __name__ == "__main__":
    request_qkd_key()
