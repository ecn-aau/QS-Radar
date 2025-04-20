import requests
import base64
import urllib.parse

SLAVE_KMS_HOST = "" # Address of KMS, maybe there is only one
SLAVE_KMS_PORT = ""
SLAVE_KMS_BASE_URL = f"https://{SLAVE_KMS_HOST}:{SLAVE_KMS_PORT}/api/v1" # KMS cert might be self-signed?
MASTER_ID = ""
KEY_ID = ""
TIMEOUT = 10
VERIFY_SSL = True # If KMS cert is self-signed, set to False, but be aware

# Unsure if needed, we will see at setup
# HEADERS = {
#     "Content-Type": "application/json",
#     "Authorization": f"Bearer {API_KEY}"
# }

def request_qkd_key_with_IDs() -> None:
    get_key_with_IDs_url = f"{SLAVE_KMS_BASE_URL}/keys/{urllib.parse.urlencode(MASTER_ID)}/dec_keys"

    # Based on https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf Table 12
    payload = {
        "key_IDs": [
            {
                "key_ID": KEY_ID,
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
    request_qkd_key_with_IDs()
