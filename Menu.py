from rich.console import Console
from rich.prompt import Prompt,IntPrompt,Confirm
from rich.table import Table
from CryptoFunctions import *


console = Console()
encrypt = Encrypt_Class()
decrypt=Decrypt_Class()
hashs = Hashs_Class()
encoder = Encode_Class()
decoder = Decode_Class()

def show_menu():
    # console.print("Please select an option:", style="bold green")
    hash_table = Table(show_header=True, header_style="bold magenta",title="Hash")
    hash_table.add_column("Option", justify="center")
    hash_table.add_column("Description")
    
    hash_table.add_row("1", "MD5 Hashing")
    hash_table.add_row("2", "Bcrypt Hashing")
    hash_table.add_row("3", "RIPEMD Hashing")
    hash_table.add_row("4", "SHA-1 Hashing")
    hash_table.add_row("5", "SHA-224 Hashing")
    hash_table.add_row("6", "SHA-256 Hashing")
    hash_table.add_row("7", "SHA-384 Hashing")
    hash_table.add_row("8", "SHA-512 Hashing")
    
    encode_table = Table(show_header=True, header_style="bold magenta",title="Encode")
    encode_table.add_column("Option", justify="center")
    encode_table.add_column("Description")
    encode_table.add_row("9", "Base64 Encoding")
    encode_table.add_row("10", "URL Encoding")
    encode_table.add_row("11", "HTML Encoding")
    
    
    decode_table = Table(show_header=True, header_style="bold magenta",title="Decode")
    decode_table.add_column("Option", justify="center")
    decode_table.add_column("Description")
    decode_table.add_row("12", "Base64 Decoding")
    decode_table.add_row("13", "URL Decoding")
    decode_table.add_row("14", "HTML Decoding")
    
    
    encrypt_table = Table(show_header=True, header_style="bold magenta",title="Encrypt")
    encrypt_table.add_column("Option", justify="center")
    encrypt_table.add_column("Description")
    encrypt_table.add_row("15", "AES Encrypt")

    decrypt_table= Table(show_header=True, header_style="bold magenta",title="Decrypt")
    decrypt_table.add_column("Option", justify="center")
    decrypt_table.add_column("Description")
    decrypt_table.add_row("16", "AES Decrypt")
    
    other_table= Table(show_header=True, header_style="bold magenta",title="Other")
    other_table.add_column("Option", justify="center")
    other_table.add_column("Description")
    other_table.add_row("0", "Exit")

    console.print(hash_table)
    console.print(encode_table)
    console.print(decode_table)
    console.print(encrypt_table)
    console.print(decrypt_table)
    console.print(other_table)

def process_choice(choice):
    if choice == "1":
        text = Prompt.ask("Enter text to hash with MD5")
        salt = Prompt.ask("Enter Salt",default="")
        result = hashs.md5(text,salt)
    elif choice == "2":
        text = Prompt.ask("Enter text to hash with Bcrypt")
        rounds = IntPrompt.ask("Enter Round",default=12)
        prefix = Prompt.ask("Enter Prefix",default="2b")
        result = hashs.bcrypt(text,rounds,prefix)
    elif choice == "3":
        text = Prompt.ask("Enter text to hash with RIPEMD")
        salt = Prompt.ask("Enter Salt",default="")
        result = hashs.ripemd(text,salt)
    elif choice == "4":
        text = Prompt.ask("Enter text to hash with SHA-1")
        salt = Prompt.ask("Enter Salt",default="")
        result = hashs.sha1(text,salt)
    elif choice == "5":
        text = Prompt.ask("Enter text to hash with SHA-224")
        salt = Prompt.ask("Enter Salt",default="")
        result = hashs.sha224(text)
    elif choice == "6":
        text = Prompt.ask("Enter text to hash with SHA-256")
        salt = Prompt.ask("Enter Salt",default="")
        result = hashs.sha256(text,salt)
    elif choice == "7":
        text = Prompt.ask("Enter text to hash with SHA-384")
        salt = Prompt.ask("Enter Salt",default="")
        result = hashs.sha384(text,salt)
    elif choice == "8":
        text = Prompt.ask("Enter text to hash with SHA-512")
        salt = Prompt.ask("Enter Salt",default="")
        result = hashs.sha512(text,salt)
    elif choice == "9":
        text = Prompt.ask("Enter text to Base64 encode")
        result = encoder.base64_encode(text)
    elif choice == "10":
        text = Prompt.ask("Enter text to URL encode")
        result = encoder.url_encode(text)
    elif choice == "11":
        text = Prompt.ask("Enter text to HTML encode")
        result = encoder.html_encode(text)
    elif choice == "12":
        text = Prompt.ask("Enter Base64 encoded text to decode")
        result = decoder.base64_decode(text)
    elif choice == "13":
        text = Prompt.ask("Enter URL encoded text to decode")
        result = decoder.url_decode(text)
    elif choice == "14":
        text = Prompt.ask("Enter HTML encoded text to decode")
        result = decoder.html_decode(text)
    elif choice == "15":
        text = Prompt.ask("Enter Text")
        password = Prompt.ask("Password", password=True)
        result = encrypt.AES_encrypt(text,password)
    elif choice == "16":
        ciphertext = Prompt.ask("Enter ciphertext(hex)")
        password = Prompt.ask("Password", password=True)
        result = decrypt.AES_decrypt(ciphertext,password)
    elif choice == "0":
        console.print("Exiting...", style="bold red")
        return False
    else:
        console.print("Invalid option, please try again.", style="bold red")
        return True

    console.print(f"Result: [bold yellow]{result}[/bold yellow]")
    if Confirm.ask("Continue?"):
        return True
    return False
