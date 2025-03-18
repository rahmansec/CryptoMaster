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


class Hashs_Class:
    """A class providing various hash function implementations."""
    
    def md5(self, text: str, salt: str = "") -> str:
        """
        Generate MD5 hash for the provided text with optional salt.
        
        Args:
            text (str): The text to hash
            salt (str, optional): Salt to add before hashing. Defaults to "".
            
        Returns:
            str: The MD5 hash as a hexadecimal string
        """
        text = salt + text
        text_byte = text.encode()
        hash_str = MD5.new(text_byte).hexdigest()
        return hash_str

    def bcrypt(self, text: str, rounds: int = 12, prefix: str = "2b") -> str:
        """
        Generate bcrypt hash for the provided text.
        
        Args:
            text (str): The text to hash
            rounds (int, optional): Number of rounds for bcrypt. Defaults to 12.
            prefix (str, optional): Prefix for bcrypt. Defaults to "2b".
            
        Returns:
            str: The bcrypt hash
        """
        prefix_byte = prefix.encode()
        text_byte = text.encode()
        salt = bcrypt.gensalt(rounds=rounds, prefix=prefix_byte)
        hash_str = bcrypt.hashpw(text_byte, salt).decode()
        return hash_str

    def ripemd(self, text: str, salt: str = "") -> str:
        """
        Generate RIPEMD-160 hash for the provided text with optional salt.
        
        Args:
            text (str): The text to hash
            salt (str, optional): Salt to add before hashing. Defaults to "".
            
        Returns:
            str: The RIPEMD-160 hash as a hexadecimal string
        """
        text = salt + text
        text_byte = text.encode()
        hash_str = RIPEMD160.new(text_byte).hexdigest()
        return hash_str

    def sha1(self, text: str, salt: str = "") -> str:
        """
        Generate SHA-1 hash for the provided text with optional salt.
        
        Args:
            text (str): The text to hash
            salt (str, optional): Salt to add before hashing. Defaults to "".
            
        Returns:
            str: The SHA-1 hash as a hexadecimal string
        """
        text = salt + text
        text_byte = text.encode()
        hash_str = SHA1.new(text_byte).hexdigest()
        return hash_str

    def sha224(self, text: str, salt: str = "") -> str:
        """
        Generate SHA-224 hash for the provided text with optional salt.
        
        Args:
            text (str): The text to hash
            salt (str, optional): Salt to add before hashing. Defaults to "".
            
        Returns:
            str: The SHA-224 hash as a hexadecimal string
        """
        text = salt + text
        text_byte = text.encode()
        hash_str = SHA224.new(text_byte).hexdigest()
        return hash_str

    def sha256(self, text: str, salt: str = "") -> str:
        """
        Generate SHA-256 hash for the provided text with optional salt.
        
        Args:
            text (str): The text to hash
            salt (str, optional): Salt to add before hashing. Defaults to "".
            
        Returns:
            str: The SHA-256 hash as a hexadecimal string
        """
        text = salt + text
        text_byte = text.encode()
        hash_str = SHA256.new(text_byte).hexdigest()
        return hash_str

    def sha384(self, text: str, salt: str = "") -> str:
        """
        Generate SHA-384 hash for the provided text with optional salt.
        
        Args:
            text (str): The text to hash
            salt (str, optional): Salt to add before hashing. Defaults to "".
            
        Returns:
            str: The SHA-384 hash as a hexadecimal string
        """
        text = salt + text
        text_byte = text.encode()
        hash_str = SHA384.new(text_byte).hexdigest()
        return hash_str

    def sha512(self, text: str, salt: str = "") -> str:
        """
        Generate SHA-512 hash for the provided text with optional salt.
        
        Args:
            text (str): The text to hash
            salt (str, optional): Salt to add before hashing. Defaults to "".
            
        Returns:
            str: The SHA-512 hash as a hexadecimal string
        """
        text = salt + text
        text_byte = text.encode()
        hash_str = SHA512.new(text_byte).hexdigest()
        return hash_str


class Encode_Class:
    """A class providing various encoding functions."""
    
    def base64_encode(self, text: str) -> str:
        """
        Encode text to Base64.
        
        Args:
            text (str): The text to encode
            
        Returns:
            str: Base64 encoded string
        """
        text_byte = text.encode()
        encode_str = base64.b64encode(text_byte).decode()
        return encode_str

    def url_encode(self, text: str) -> str:
        """
        URL encode the provided text.
        
        Args:
            text (str): The text to encode
            
        Returns:
            str: URL encoded string
        """
        encoded = urllib.parse.quote(text)
        return encoded

    def html_encode(self, text: str) -> str:
        """
        HTML encode the provided text.
        
        Args:
            text (str): The text to encode
            
        Returns:
            str: HTML encoded string
        """
        encoded = html.escape(text)
        return encoded


class Decode_Class:
    """A class providing various decoding functions."""
    
    def base64_decode(self, encoded_text: str) -> str:
        """
        Decode Base64 encoded text.
        
        Args:
            encoded_text (str): The Base64 encoded text
            
        Returns:
            str: Decoded string
            
        Raises:
            Exception: If decoding fails
        """
        try:
            decoded_bytes = base64.b64decode(encoded_text)
            return decoded_bytes.decode()
        except Exception as e:
            return f"Error: {str(e)}"

    def url_decode(self, encoded_text: str) -> str:
        """
        URL decode the provided text.
        
        Args:
            encoded_text (str): The URL encoded text
            
        Returns:
            str: Decoded string
        """
        try:
            decoded = urllib.parse.unquote(encoded_text)
            return decoded
        except Exception as e:
            return f"Error: {str(e)}"

    def html_decode(self, encoded_text: str) -> str:
        """
        HTML decode the provided text.
        
        Args:
            encoded_text (str): The HTML encoded text
            
        Returns:
            str: Decoded string
        """
        decoded = html.unescape(encoded_text)
        return decoded


class Encrypt_Class:
    """A class providing encryption functions."""
    
    def AES_encrypt(self, input: str, password: str) -> str:
        """
        Encrypt text using AES encryption with the provided password.
        
        Args:
            input (str): The text to encrypt
            password (str): The password for encryption
            
        Returns:
            str: Encrypted text in hexadecimal format
        """
        try:
            data = input.encode()
            hash = Hashs_Class().sha256(password)
            key = bytes.fromhex(hash)
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(data, AES.block_size))
            combined = iv + ciphertext
            return combined.hex()
        except Exception as e:
            return f"Encryption Error: {str(e)}"


class Decrypt_Class:
    """A class providing decryption functions."""
    
    def AES_decrypt(self, ciphertext: str, password: str) -> str:
        """
        Decrypt AES encrypted text with the provided password.
        
        Args:
            ciphertext (str): The encrypted text in hexadecimal format
            password (str): The password for decryption
            
        Returns:
            str: Decrypted text or error message
        """
        try:
            combined = bytes.fromhex(ciphertext)
            iv = combined[:16]
            ciphertext_bytes = combined[16:]
            hash = Hashs_Class().sha256(password)
            key = bytes.fromhex(hash)
            
            decipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(decipher.decrypt(ciphertext_bytes), AES.block_size)
            return plaintext.decode()
        except Exception as e:
            return f"Decryption Error: {str(e)}"
