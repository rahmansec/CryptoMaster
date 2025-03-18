# CryptoMaster

<div align="center">
  <img src="logo.png" alt="CryptoMaster Logo" width="150"/>
  <h3>A Comprehensive Cryptography Toolkit</h3>
</div>

## Overview

**CryptoMaster** is a powerful and user-friendly command-line utility designed for cryptographic operations. This robust toolkit provides a comprehensive suite of functions for hashing, encoding/decoding, and encryption/decryption, serving as an essential resource for security professionals, developers, and enthusiasts.

## Features

### Hashing
- **MD5** - Fast hash function (not recommended for security-critical applications)
- **Bcrypt** - Strong password hashing with salt and adjustable complexity
- **RIPEMD-160** - 160-bit cryptographic hash function
- **SHA-1** - 160-bit hash function (legacy, not recommended for security-critical applications)
- **SHA-224** - 224-bit hash function from the SHA-2 family
- **SHA-256** - 256-bit hash function from the SHA-2 family
- **SHA-384** - 384-bit hash function from the SHA-2 family
- **SHA-512** - 512-bit hash function from the SHA-2 family

### Encoding / Decoding
- **Base64** - Standard encoding for binary data
- **URL** - Safe character encoding for URLs
- **HTML** - Encoding for HTML entities

### Encryption / Decryption
- **AES** - Advanced Encryption Standard with secure key derivation

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Setup
1. Clone the repository or download the source code:
   ```bash
   git clone https://github.com/rahmansec/CryptoMaster.git
   cd CryptoMaster
   ```

2. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv .venv
   
   # On Windows
   .venv\Scripts\activate
   
   # On macOS/Linux
   source .venv/bin/activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Command Line Interface

To launch the CryptoMaster application with its interactive menu:

```bash
python CryptoMaster.py
```

You'll be presented with a menu of options to choose from.

### In Your Python Code

You can also import and use CryptoMaster functions directly in your Python projects:

```python
# Import the classes you need
from CryptoFunctions import Hashs_Class, Encode_Class, Decrypt_Class

# Hash example
hasher = Hashs_Class()
hash_result = hasher.sha256("password123", salt="mysalt")
print(f"SHA-256 Hash: {hash_result}")

# Encoding example
encoder = Encode_Class()
encoded = encoder.base64_encode("Hello, World!")
print(f"Base64 Encoded: {encoded}")

# Encryption example
from CryptoFunctions import Encrypt_Class
encryptor = Encrypt_Class()
encrypted = encryptor.AES_encrypt("Sensitive data", "secure_password")
print(f"AES Encrypted: {encrypted}")
```

## API Reference

### Hashing Functions

- `md5(text, salt="")` - Generates MD5 hash
- `bcrypt(text, rounds=12, prefix="2b")` - Generates Bcrypt hash 
- `ripemd(text, salt="")` - Generates RIPEMD-160 hash
- `sha1(text, salt="")` - Generates SHA-1 hash
- `sha224(text, salt="")` - Generates SHA-224 hash
- `sha256(text, salt="")` - Generates SHA-256 hash
- `sha384(text, salt="")` - Generates SHA-384 hash
- `sha512(text, salt="")` - Generates SHA-512 hash

### Encoding Functions

- `base64_encode(text)` - Encodes text to Base64
- `url_encode(text)` - URL encodes text
- `html_encode(text)` - HTML encodes text

### Decoding Functions

- `base64_decode(encoded_text)` - Decodes Base64 text
- `url_decode(encoded_text)` - Decodes URL encoded text
- `html_decode(encoded_text)` - Decodes HTML encoded text

### Encryption Functions

- `AES_encrypt(input, password)` - Encrypts text using AES

### Decryption Functions

- `AES_decrypt(ciphertext, password)` - Decrypts AES encrypted text

## Security Considerations

- **MD5 and SHA-1** are provided for compatibility purposes but should not be used for security-critical applications as they have known vulnerabilities.
- For password storage, **Bcrypt** is recommended due to its built-in salt and computational cost settings.
- For general secure hashing, consider using **SHA-256** or stronger.
- When using AES encryption, use strong, unique passwords to ensure data security.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [PyCryptodome](https://pycryptodome.readthedocs.io/) for cryptographic primitives
- [Rich](https://rich.readthedocs.io/) for beautiful terminal output
- [Typer](https://typer.tiangolo.com/) for CLI features

