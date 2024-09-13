from rich.prompt import Prompt
from Menu import show_menu ,process_choice
from Banner import banner

def main():
    while True:
        show_menu()
        choice = Prompt.ask("Enter your choice")
        if not process_choice(choice):
            break

if __name__ == "__main__":
    banner()
    main()
