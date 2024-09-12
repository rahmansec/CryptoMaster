import urllib.parse
import bcrypt
from Crypto.Hash import RIPEMD160, MD5, SHA1, SHA224, SHA256, SHA384, SHA512
import base64
import urllib
import html

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

    def unicode_encode(self, text: str):
        encoded = text.encode("utf-8")
        return encoded

    def html_encode(self,text:str):
        encoded = html.escape(text)
        return encoded
    
    
class Decode_Class():
    def base64_decode(self, encoded_text: str):
        decoded_bytes = base64.b64decode(encoded_text)
        return decoded_bytes.decode()
    
    def url_decode(self, encoded_text: str):
        decoded = urllib.parse.unquote(encoded_text)
        return decoded        
    
    def unicode_decode(self, encoded_text: bytes):
        decoded = encoded_text.decode("utf-8")
        return decoded
    
    def html_decode(self, encoded_text: str):
        decoded = html.unescape(encoded_text)
        return decoded        