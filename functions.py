import bcrypt
from Crypto.Hash import RIPEMD160, MD5, SHA1, SHA224, SHA256, SHA384, SHA512
import base64

class Class_Hashs:
    def md5(self, text: str,salt:str=""):
        text = salt+text
        text_byte = text.encode()
        hash_str = MD5.new(text_byte).hexdigest()
        return hash_str

    def bcrypt(self, text: str,rounds: int = 12, prefix: str = "2b"):
        prefix_byte = prefix.encode()
        text_byte = text.encode()
        salt = bcrypt.gensalt(rounds=rounds, prefix=prefix_byte)
        hash_str = bcrypt.hashpw(text_byte, salt).decode()
        return hash_str

    def ripemd(self, text: str,salt:str=""):
        text = salt+text
        text_byte = text.encode()
        hash_str = RIPEMD160.new(text_byte).hexdigest()
        return hash_str

    def sha1(self, text: str,salt:str=""):
        text = salt+text
        text_byte = text.encode()
        hash_str = SHA1.new(text_byte).hexdigest()
        return hash_str

    def sha224(self, text: str,salt:str=""):
        text = salt+text
        text_byte = text.encode()
        hash_str = SHA224.new(text_byte).hexdigest()
        return hash_str

    def sha256(self, text: str,salt:str=""):
        text = salt+text
        text_byte = text.encode()
        hash_str = SHA256.new(text_byte).hexdigest()
        return hash_str

    def sha384(self, text: str,salt:str=""):
        text = salt+text
        text_byte = text.encode()
        hash_str = SHA384.new(text_byte).hexdigest()
        return hash_str

    def sha512(self, text: str,salt:str=""):
        text = salt+text
        text_byte = text.encode()
        hash_str = SHA512.new(text_byte).hexdigest()
        return hash_str


class Class_Encrypt():
    def base64(self,text:str):
        text_byte = text.encode()
        encode_str = base64.b64encode(text_byte).decode()
        return encode_str

   
