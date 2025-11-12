import oqs
import json
import base64

from Crypto.PublicKey import RSA

SIGALG = "RSA" # Options: RSA, ML-DSA-44, ML-DSA-65, ML-DSA-87

if SIGALG == "RSA":
    # Generate key pair
    key = RSA.generate(3072)
    public_key = key.publickey().exportKey()
    private_key = key.exportKey()

    # Save key pair to file
    with open("ppk-"+SIGALG+".json", "w") as file:
        ppk = {
            "public_key": base64.b64encode(public_key).decode(),
            "private_key": base64.b64encode(private_key).decode()
        }
        file.write(json.dumps(ppk))
else:
    with oqs.Signature(SIGALG) as signer, open("ppk-"+SIGALG+".json", "w") as file:
        # Generate key pair
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()

        # Save key pair to file
        ppk = {
            "public_key": base64.b64encode(public_key).decode(),
            "private_key": base64.b64encode(private_key).decode()
        }
        file.write(json.dumps(ppk))