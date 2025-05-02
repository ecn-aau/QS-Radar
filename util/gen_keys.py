import oqs
import base64
import json


sigalg = "ML-DSA-87"

def gen_keys() -> object:
    key_data = {}

    # Generate Client A keys
    public_key, private_key = gen_keys_general()
    base64_public_key, base64_private_key = encode_keys_base64(public_key, private_key)
    clientA_key_data = {
        "public_key": base64_public_key,
        "private_key": base64_private_key,
    }
    key_data["clientA"] = clientA_key_data
    print_keys("ClientA", base64_public_key, base64_private_key)

    with open("clientA_keys.json", "w") as clientA_file:
        json.dump(clientA_key_data, clientA_file, indent=4)

    # Generate Client B keys
    public_key, private_key = gen_keys_general()
    base64_public_key, base64_private_key = encode_keys_base64(public_key, private_key)
    key_data["clientB"] = {
        "public_key": base64_public_key,
        "private_key": base64_private_key,
    }
    print_keys("ClientB", base64_public_key, base64_private_key)

    # Persist keys in file
    with open("keys.json", "w") as file:
        json.dump(key_data, file, indent=4)


def gen_keys_general() -> tuple[bytes, bytes]:
    with oqs.Signature(sigalg) as sign:
        return (sign.generate_keypair(), sign.export_secret_key())


def encode_keys_base64(pub_key: bytes, priv_key: bytes) -> tuple[str, str]:
    return (base64.b64encode(pub_key).decode('utf-8'), base64.b64encode(priv_key).decode('utf-8'))


def print_keys(entity: str, pub_key: str, priv_key: str) -> None:
    print(f"------ {entity} keys ------")
    print(f"Public key base64: {pub_key}")
    print(f"Private key base64: {priv_key}\n")


if __name__ == "__main__":
    gen_keys()
