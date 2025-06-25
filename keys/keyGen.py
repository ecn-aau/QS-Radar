import oqs
import json

SIGALG = "ML-DSA-87"

with oqs.Signature(SIGALG) as signer, open("ppk.json", "w") as file:
    # Generate key pair
    public_key = signer.generate_keypair()
    private_key = signer.export_secret_key()
    ppk = {
        "public_key": public_key,
        "private_key": private_key
    }

    # Save key pair to file
    file.write(json.dumps(ppk))