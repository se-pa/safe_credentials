import argparse
import os.path
import sys
import csv, operator
import cryptography
import secrets
import base64
import getpass
import re
import urllib.parse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from tabulate import tabulate


def main():

    """
    Define Argument Parser with description.
    Set default argument for database and optional for customized database selection.
    Check file with function
    """
    parser = argparse.ArgumentParser(
        description="SAFE CREDENTIALS in encrypted database. Remove database.csv and database.salt to reset program."
    )
    parser.add_argument(
        "-d",
        "--d",
        dest="filename",
        default="database.csv",
        metavar="file",
        help="select database file (*.csv)",
        type=check_file,
    )

    args = parser.parse_args()

    """
    If database was found, ask user for password and generey key for decrypt database.
    Create temporary list in memory and encrypt file.
    """
    password = getpass.getpass("Input password to decrypt database: ")
    f_name = os.path.splitext(args.filename)[0]
    key = generate_key(password, load_salt=True, saltname=f"{f_name}.salt")

    """ Temporary list from file """
    decrypt(args.filename, key)
    list_entries = temp_list(args.filename)
    encrypt(args.filename, key)
    print(tabulate([["Database decrypted successfully."]], tablefmt="grid"))

    """
    Ask user for action:
    list - list all entires in database
    add - new entry in database
    search - search for entry
    exit - quit program
    """

    while True:

        action = input(
            "Commands:\nlist - list all entries in the database\nadd - add new entry to database\nsearch - search for an entry in the database\ndel - delete an item from the database\nexit - quit the program\n"
        )

        """ Sort list and use tabulate to print table in grid format with header of first row """
        if action.lower().strip() == "list":
            list_header = []
            list_entries = sorted(list_entries, key=operator.itemgetter(0))
            list_header.append(["URL / TITLE", "LOGIN", "PASSWORD", "NOTE"])
            for row in list_entries:
                list_header.append(row)
            print(tabulate(list_header, headers="firstrow", tablefmt="grid"))

        """ Add new entries with urlparse. Strip everything without path (host name). """
        if action.lower().strip() == "add":
            url = input("URL / Title: ")
            url = urlparse(url)
            url = url.hostname
            login = input("Login: ").strip()
            password = input("Password: ").strip()
            note = input("Note: ").strip()
            fields = [url.lstrip("w."), login, password, note]
            list_entries.append(fields)
            print(tabulate([["The entry has been added."]], tablefmt="grid"))

        """ Search for entry in database with urlprase included """
        if action.lower().strip() == "search":
            user_search = urlparse(input("Enter URL / Title for search: "))
            count = len(list_entries)
            for row in list_entries:
                if user_search.hostname in row[0]:
                    count -= 1
                    entries = [
                        ["URL / TITLE", "LOGIN", "PASSWORD", "NOTE"],
                        [row[0], row[1], row[2], row[3]],
                    ]
                    print(tabulate(entries, headers="firstrow", tablefmt="grid"))

            if count == len(list_entries):
                print(tabulate([["No result found."]], tablefmt="grid"))

        """ Remove: Search for entry and ask if user want to remove from database """
        if action.lower().strip() == "del":

            rows = list()
            user_search = urlparse(
                input("Enter exact URL / Title to remove it from database: ")
            )
            for row in list_entries:
                rows.append(row)
                for delete in row:
                    if user_search.hostname == delete:
                        enties = [
                            ["URL / TITLE", "LOGIN", "PASSWORD", "NOTE"],
                            [row[0], row[1], row[2], row[3]],
                        ]
                        print(tabulate(enties, headers="firstrow", tablefmt="grid"))
                        rows.remove(row)
            ask = input("Are you sure (Y/N)? ")
            if confirm(ask):
                list_entries = rows
                print(tabulate([["The entry has been removed."]], tablefmt="grid"))

        """ Exit after working on database """
        if action.lower().strip() == "exit":
            decrypt(args.filename, key)
            with open(args.filename, "w") as f:
                writer = csv.writer(f)
                writer.writerows(list_entries)
                f.close()
            encrypt(args.filename, key)
            print(tabulate([["Database encrypted successfully."]], tablefmt="grid"))
            break


def temp_list(filename: str) -> list:
    """Create temporary sorted list with entries from CSV and print table for the user with tabulate library"""
    entries = []
    with open(filename) as file:
        reader = csv.reader(file)
        for row in reader:
            entries.append(row)
    return entries


def urlparse(url: str) -> urllib.parse.ParseResult:
    """URL parser for every type of url"""
    if not re.search(r"^[A-Za-z0-9+.\-]+://", url):
        url = f"tcp://{url}"
    return urllib.parse.urlparse(url)


def check_file(file: str) -> str:
    """
    Check if database file exists,
    if not, ask for create.
    Rise errors for wrong inputs
    """
    if not os.path.exists(file):
        if file == "database.csv":
            create_database()
            return file
        else:
            raise argparse.ArgumentTypeError(f"\nThe file {file} not found")
    elif not file.endswith(".csv"):
        raise argparse.ArgumentTypeError("\nInvalid input file")
    else:
        return file


def create_database():
    """
    If user agree, create default database file and encrypt.
    If not agree, exit program
    """
    create = input(
        tabulate([["Database does not exist. Create database (Y/N)?"]], tablefmt="grid")
        + "\n"
    )
    if confirm(create):
        password = getpass.getpass("Input password for database: ")
        password_check = getpass.getpass("Repeat password for database: ")
        if password != password_check:
            sys.exit(tabulate([["Passwords do not match."]], tablefmt="grid"))

        with open("database.csv", "w", newline="") as f:
            writer = csv.writer(f)
            f.close()

        f_name = os.path.splitext(f.name)[0]

        key = generate_key(password, salt_size=32, save_salt=True, saltname=f_name)
        encrypt("database.csv", key)
        print(
            tabulate(
                [["The database: database.csv has been created."]], tablefmt="grid"
            )
        )
    else:
        sys.exit(0)


def confirm(string: str) -> bool:
    """Check if user agree, return true"""
    if (
        string.lower().strip() == "y"
        or string.lower().strip() == "yes"
        or string.lower().strip() == "ye"
    ):
        return True


def generate_key(
    password: str, saltname: str, salt_size=32, load_salt=False, save_salt=True
) -> bytes:
    """
    Combaine password with salt and generate key
    Generates a key from a `password` and the salt.
    (Salt is a fixed-length cryptographically-strong random value
    that is added to the input of hash functions to create unique hashes for every input)
    """

    """
    If check if salt already exist and read bytes from file,
    else generate salt
    """

    if load_salt:
        salt = open(f"{saltname}", "rb").read()
    elif save_salt:
        """generate salt with size 32"""
        salt = secrets.token_bytes(salt_size)
        with open(f"{saltname}.salt", "wb") as salt_file:
            salt_file.write(salt)

    """Get key from derive of passed password and salt file"""
    key_derive = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    derived_key = key_derive.derive(password.encode())

    """ encode derived key with base 64, binary-to-text encoding """
    return base64.urlsafe_b64encode(derived_key)


def encrypt(filename: str, key: bytes):
    """
    Encrypt file with symmetric encryption (Fernet) providing filename and key
    """
    f = Fernet(key)
    """ Read data from file, encrypt it and then write to file """
    with open(filename, "rb") as file:
        file_data = file.read()
    token = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(token)


def decrypt(filename: str, key: bytes):
    """
    Decrypt file with fermet providing filename and key
    """
    f = Fernet(key)

    """ Read encrypted data from file and try to encrypt. Successful write decrypted data to file,
    else rise error """
    with open(filename, "rb") as file:
        token = file.read()
    try:
        decrypted_token = f.decrypt(token)
    except cryptography.fernet.InvalidToken:

        return sys.exit(
            tabulate([["Invalid password or salt file, try again."]], tablefmt="grid")
        )
    with open(filename, "wb") as file:
        file.write(decrypted_token)


if __name__ == "__main__":
    """Elegant error for key interrupt"""
    try:
        main()
    except KeyboardInterrupt:
        print("Key interrupt")
        sys.exit(1)
