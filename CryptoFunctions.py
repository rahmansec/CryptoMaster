import urllib.parse
import bcrypt
from Crypto.Hash import RIPEMD160, MD5, SHA1, SHA224, SHA256, SHA384, SHA512
import base64
import urllib
import html
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from rich.prompt import Prompt
import typer


class Hashs_Class:
    def md5(self, text: str, salt: str = ""):
        text = salt + text
        text_byte = text.encode()
        hash_str = MD5.new(text_byte).hexdigest()
        return hash_str

    def bcrypt(self, text: str, rounds: int = 12, prefix: str = "2b"):
        prefix_byte = prefix.encode()
        text_byte = text.encode()
        salt = bcrypt.gensalt(rounds=rounds, prefix=prefix_byte)
        hash_str = bcrypt.hashpw(text_byte, salt).decode()
        return hash_str

    def ripemd(self, text: str, salt: str = ""):
        text = salt + text
        text_byte = text.encode()
        hash_str = RIPEMD160.new(text_byte).hexdigest()
        return hash_str

    def sha1(self, text: str, salt: str = ""):
        text = salt + text
        text_byte = text.encode()
        hash_str = SHA1.new(text_byte).hexdigest()
        return hash_str

    def sha224(self, text: str, salt: str = ""):
        text = salt + text
        text_byte = text.encode()
        hash_str = SHA224.new(text_byte).hexdigest()
        return hash_str

    def sha256(self, text: str, salt: str = ""):
        text = salt + text
        text_byte = text.encode()
        hash_str = SHA256.new(text_byte).hexdigest()
        return hash_str

    def sha384(self, text: str, salt: str = ""):
        text = salt + text
        text_byte = text.encode()
        hash_str = SHA384.new(text_byte).hexdigest()
        return hash_str

    def sha512(self, text: str, salt: str = ""):
        text = salt + text
        text_byte = text.encode()
        hash_str = SHA512.new(text_byte).hexdigest()
        return hash_str


class Encode_Class:
    def base64_encode(self, text: str):
        text_byte = text.encode()
        encode_str = base64.b64encode(text_byte).decode()
        return encode_str

    def url_encode(self, text: str):
        encoded = urllib.parse.quote(text)
        return encoded

    def html_encode(self, text: str):
        encoded = html.escape(text)
        return encoded


class Decode_Class:
    def base64_decode(self, encoded_text: str):
        decoded_bytes = base64.b64decode(encoded_text)
        return decoded_bytes.decode()

    def url_decode(self, encoded_text: str):
        decoded = urllib.parse.unquote(encoded_text)
        return decoded

    def html_decode(self, encoded_text: str):
        decoded = html.unescape(encoded_text)
        return decoded


class Encrypt_Class:
    def AES_encrypt(self, input: str, password: str):
        data = input.encode()
        hash = Hashs_Class().sha256(password)
        key = bytes.fromhex(hash)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        combined = iv + ciphertext
        return combined.hex()


class Decrypt_Class:
    def AES_decrypt(self, ciphertext: str, password: str):
        combined = bytes.fromhex(ciphertext)
        iv = combined[:16]
        ciphertext_bytes = combined[16:]
        hash = Hashs_Class().sha256(password)
        key = bytes.fromhex(hash)
        try:
            decipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(decipher.decrypt(ciphertext_bytes), AES.block_size)
            return plaintext.decode()
        except:
            return typer.secho("Faild...", fg="red")
