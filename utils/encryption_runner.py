import subprocess
import json

def run_decrypt_js(operation, data):
    result = subprocess.run(['node', '../scripts/decrypt.js', operation, json.dumps(data)], capture_output=True, text=True)
    return json.loads(result.stdout)

def encrypt(text, key, iv):
    return run_decrypt_js('encrypt', {'text': text, 'key': key, 'iv': iv})

def decrypt(encrypted_text, key, iv):
    return run_decrypt_js('decrypt', {'encryptedText': encrypted_text, 'key': key, 'iv': iv})

if __name__ == "__main__":
    config = {
        "aes_key": "your_aes_key",
        "iv": "your_iv"
    }
    encrypted = encrypt("Hello, World!", config["aes_key"], config["iv"])
    print(encrypted)
    decrypted = decrypt(encrypted, config["aes_key"], config["iv"])
    print(decrypted)