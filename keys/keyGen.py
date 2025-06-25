import oqs
import json
import base64

SIGALG = "ML-DSA-87"

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