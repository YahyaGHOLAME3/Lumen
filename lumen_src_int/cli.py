
from .menus import internal_menu, external_menu

def main():
    while True:
        print("\n[+] Lumen Scan Menu:")
        print("1. Internal Pentest")
        print("2. External Pentest")
        print("q. Quit\n")
        choice = input(">> ").strip()
        if choice == '1':
            internal_menu.run()
        elif choice == '2':
            external_menu.run()
        elif choice.lower() == 'q':
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Please select 1, 2, or q.")

if __name__ == "__main__":
    main()
