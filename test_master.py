import unittest
import json
import base64
import oqs

from master import sign_data, encrypt_data, ENCODING, SIGALG
from Crypto.Cipher import AES

MESSAGE = b"Hello world!"
KEY = b"asdl3532mv,+b921nvk@wl342l.9fPeQ"

MOCK_DATA = {
    "nonce": "TZIR5pWqd39TIEoroGJ+UQ==",
    "ciphertext": "f04gUa8IHTWEUuJw",
    "tag": "NwBzXcs041ZS3mwNmruSNg==",
}
MOCK_KEY_ID = "bc077000-d4db-499d-b093-d24fe5d33be0"


class TestMasterUtils(unittest.TestCase):
    def test_sign_data_true(self):
        with open("master_keys.json", "r") as file:
            data = json.load(file)
        public_key = data["public_key"]
        public_key = base64.b64decode(public_key)
        verifier = oqs.Signature(SIGALG, public_key)

        verification_data = MOCK_DATA
        verification_data["key_ID"] = MOCK_KEY_ID
        verification_data = json.dumps(verification_data, sort_keys=True).encode(ENCODING)

        signed_data = sign_data(MOCK_DATA, MOCK_KEY_ID)
        signature = signed_data["signature"]
        signature_bytes = base64.b64decode(signature)

        self.assertTrue(verifier.verify(verification_data, signature_bytes, public_key))

    def test_sign_data_message_false(self):
        with open("master_keys.json", "r") as file:
            data = json.load(file)
        public_key = data["public_key"]
        public_key = base64.b64decode(public_key)
        verifier = oqs.Signature(SIGALG, public_key)

        verification_data = {
            "heehe": "lófasz"
        }
        verification_data["key_ID"] = "aSASDASDASD"
        verification_data = json.dumps(verification_data, sort_keys=True).encode(ENCODING)

        signed_data = sign_data(MOCK_DATA, MOCK_KEY_ID)
        signature = signed_data["signature"]
        signature_bytes = base64.b64decode(signature)

        self.assertFalse(verifier.verify(verification_data, signature_bytes, public_key))

    def test_sign_data_key_false(self):
        with open("master_keys.json", "r") as file:
            data = json.load(file)
        public_key = data["public_key"]
        public_key = base64.b64decode(public_key)

        # Play around with the key
        mutable_pubkey = bytearray(public_key)
        for i in range(0, len(mutable_pubkey), 100):
            mutable_pubkey[i] = 0xFF
        public_key = bytes(mutable_pubkey)

        verifier = oqs.Signature(SIGALG, public_key)

        verification_data = MOCK_DATA
        verification_data["key_ID"] = MOCK_KEY_ID
        verification_data = json.dumps(verification_data, sort_keys=True).encode(ENCODING)

        signed_data = sign_data(MOCK_DATA, MOCK_KEY_ID)
        signature = signed_data["signature"]
        signature_bytes = base64.b64decode(signature)

        self.assertFalse(verifier.verify(verification_data, signature_bytes, public_key))

    
    def test_encrypt_data_true(self):
        encrypted_data = encrypt_data(MESSAGE, KEY)
        nonce = base64.b64decode(encrypted_data["nonce"])
        tag = base64.b64decode(encrypted_data["tag"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])

        decipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
        decrypted = decipher.decrypt_and_verify(ciphertext, tag)

        self.assertEqual(decrypted, MESSAGE)

    def test_encrypt_data_key_false(self):
        encrypted_data = encrypt_data(MESSAGE, b"asda2342gfsdbvdas43b34hg2352nvak")
        nonce = base64.b64decode(encrypted_data["nonce"])
        tag = base64.b64decode(encrypted_data["tag"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])

        decipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
        with self.assertRaises(ValueError):
            decipher.decrypt_and_verify(ciphertext, tag)

    def test_encrypt_data_message_false(self):
        encrypted_data = encrypt_data(b"asdasvsw345+", KEY)
        nonce = base64.b64decode(encrypted_data["nonce"])
        tag = base64.b64decode(encrypted_data["tag"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])

        decipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
        decrypted = decipher.decrypt_and_verify(ciphertext, tag)

        self.assertNotEqual(decrypted, MESSAGE)

if __name__ == '__main__':
    unittest.main()
