from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from Encoder import *


console = Console()

hashs = Hashs_Class()
encoder = Encode_Class()
decoder = Decode_Class()

def show_menu():
    console.print("Please select an option:", style="bold green")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Option", justify="center")
    table.add_column("Description")
    
    table.add_row("1", "MD5 Hashing")
    table.add_row("2", "Bcrypt Hashing")
    table.add_row("3", "RIPEMD Hashing")
    table.add_row("4", "SHA-1 Hashing")
    table.add_row("5", "SHA-224 Hashing")
    table.add_row("6", "SHA-256 Hashing")
    table.add_row("7", "SHA-384 Hashing")
    table.add_row("8", "SHA-512 Hashing")
    table.add_row("9", "Base64 Encoding")
    table.add_row("10", "URL Encoding")
    table.add_row("11", "Unicode Encoding")
    table.add_row("12", "HTML Encoding")
    table.add_row("13", "Base64 Decoding")
    table.add_row("14", "URL Decoding")
    table.add_row("15", "Unicode Decoding")
    table.add_row("16", "HTML Decoding")
    table.add_row("0", "Exit")

    console.print(table)

def process_choice(choice):
    if choice == "1":
        text = Prompt.ask("Enter text to hash with MD5")
        result = hashs.md5(text)
    elif choice == "2":
        text = Prompt.ask("Enter text to hash with Bcrypt")
        result = hashs.bcrypt(text)
    elif choice == "3":
        text = Prompt.ask("Enter text to hash with RIPEMD")
        result = hashs.ripemd(text)
    elif choice == "4":
        text = Prompt.ask("Enter text to hash with SHA-1")
        result = hashs.sha1(text)
    elif choice == "5":
        text = Prompt.ask("Enter text to hash with SHA-224")
        result = hashs.sha224(text)
    elif choice == "6":
        text = Prompt.ask("Enter text to hash with SHA-256")
        result = hashs.sha256(text)
    elif choice == "7":
        text = Prompt.ask("Enter text to hash with SHA-384")
        result = hashs.sha384(text)
    elif choice == "8":
        text = Prompt.ask("Enter text to hash with SHA-512")
        result = hashs.sha512(text)
    elif choice == "9":
        text = Prompt.ask("Enter text to Base64 encode")
        result = encoder.base64_encode(text)
    elif choice == "10":
        text = Prompt.ask("Enter text to URL encode")
        result = encoder.url_encode(text)
    elif choice == "11":
        text = Prompt.ask("Enter text to Unicode encode")
        result = encoder.unicode_encode(text)
    elif choice == "12":
        text = Prompt.ask("Enter text to HTML encode")
        result = encoder.html_encode(text)
    elif choice == "13":
        text = Prompt.ask("Enter Base64 encoded text to decode")
        result = decoder.base64_decode(text)
    elif choice == "14":
        text = Prompt.ask("Enter URL encoded text to decode")
        result = decoder.url_decode(text)
    elif choice == "15":
        text = Prompt.ask("Enter Unicode encoded bytes (e.g. b'example')")
        result = decoder.unicode_decode(eval(text))  # Caution: eval should be used carefully
    elif choice == "16":
        text = Prompt.ask("Enter HTML encoded text to decode")
        result = decoder.html_decode(text)
    elif choice == "0":
        console.print("Exiting...", style="bold red")
        return False
    else:
        console.print("Invalid option, please try again.", style="bold red")
        return True

    console.print(f"Result: [bold yellow]{result}[/bold yellow]")
    return True
