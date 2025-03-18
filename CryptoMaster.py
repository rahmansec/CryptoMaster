#!/usr/bin/env python3
"""
CryptoMaster - A comprehensive cryptography toolkit

This is the main entry point for the CryptoMaster application,
providing access to various cryptographic operations including hashing,
encoding/decoding, and encryption/decryption.
"""

from rich.prompt import Prompt
from rich.console import Console
from Menu import show_menu, process_choice
from Banner import banner


console = Console()


def main():
    """
    Main application loop.
    
    Continuously displays menu and processes user choices until
    the user chooses to exit.
    """
    try:
        while True:
            show_menu()
            choice = Prompt.ask("Enter your choice")
            if not process_choice(choice):
                break
    except KeyboardInterrupt:
        console.print("\nProgram terminated by user.", style="bold red")
    except Exception as e:
        console.print(f"\nAn unexpected error occurred: {str(e)}", style="bold red")
    finally:
        console.print("Thanks for using CryptoMaster!", style="bold green")


if __name__ == "__main__":
    banner()
    main()
