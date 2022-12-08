# **SAFE CREDENTIALS**
### **Video Demo:**  [link](https://youtu.be/pnMG-DS3jyw)

**Description:** A simple program which allows the user to create an encrypted database to store logins, passwords and notes related to the URL / title. The program requires the creation of a database, and the user is prompted to confirm. After acceptance, a new password needs to be provided and repeated. After that, the encrypted database will be created. After that, the encrypted database will be created. In the next step user needs to provide the password to decrypt and login into an existing database. The following commands are available: list - list all entries in the database, add - add new entry to database, search - search for an entry in the database, del - delete an item, exit - quit the program.

The program consists of nine functions, including main(), to check for input the database with Argument Parser. The default database is set to database.csv, but the user can select other file with an optional argument: -d 'example_database_csv'. Help for the usage of the program is included with an optional argument: -h. Function check_file() used for type in Argument Parser with check for database file.
If the program does not find it, then it will trigger the create_database() functon and ask the user for confirmation and create a new database with the provided password. While creating the database, generate_key() function creates the key from a combination of password and salt file. Salt is a fixed-length cryptographically-strong random value created from the system. With generated key program encrypts the database with encrypt() function. Encryption takes place with symmetric encryption (Fernet) by reading bytes from file and replacing them with encrypted data. After loading the correct database, main() will ask for the password to use the decrypt() database (which works using an inverse way to encrypt()). Then Creates a temporary database in memory and immediately encrypts CSV file. Program design with decrypt, read to memory and encrypt database at the beginning was used because of security reasons (program interruption, protect from CSV file manual reading). The user is asked for input:

**list** - Append sorted entries from temporary list to an empty list with header and print with Tabulate table.

**add** - Ask the user for URL / title, login, password and note and append entry to the temporary list. Use urlparse() function to strip any string before hostname ('www.', 'https://', etc.).

**search** - search for an entry in the database and print using Tabulate table with a header.

**del** - search for an entry in temporary the database, ask for user confirmation with confirm() fuction then delete from temp list.

**exit** - Decrypt database file, append an actual temporary list to database.csv, encrypt file and quit the program.

### Project file list description:

    safe_credentials.py - program file
    README.md - project documentation
    test_safe_credentials.py - function tests using pytest
    test_database.csv - sample file for tests

