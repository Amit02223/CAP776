import csv
import bcrypt
import requests
import re
import sys
from tabulate import tabulate


CSV_FILE = 'Details.csv'
MAX_LOGIN_ATTEMPTS = 5
OPENLIBRARY_API_URL = 'http://openlibrary.org/search.json'


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

def password_validation(password):
    if (len(password) >= 8 and 
        re.search("[a-z]", password) and 
        re.search("[A-Z]", password) and 
        re.search("[0-9]", password) and 
        re.search("[@#$%^&+=]", password)):
        return True
    return False


def read_csv():
    users = []
    try:
        with open(CSV_FILE, mode='r') as file:
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                users.append(row)
    except FileNotFoundError:
        pass
    return users

def write_csv(users):
    fieldnames = ['email', 'hashed_password', 'security_question', 'security_answer']
    with open(CSV_FILE, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(users)


def register_user():
    email = input("Enter your email: ").strip()
    users = read_csv()
    
    
    for user in users:
        if user['email'] == email:
            print("Email already registered!")
            return
    
    while True:
        password = input("Enter a secure password: ").strip()
        if password_validation(password):
            break
        else:
            print("Password must be at least 8 characters long, with an uppercase letter, lowercase letter, number, and special character.")
    
    hashed_password = hash_password(password)
    security_question = input("Enter a security question: ").strip()
    security_answer = input("Enter the answer to your security question: ").strip()
    
    new_user = {
        'email': email,
        'hashed_password': hashed_password.decode('utf-8'),
        'security_question': security_question,
        'security_answer': security_answer
    }
    
    users.append(new_user)
    write_csv(users)
    print("Registration successful!")


def login_user():
    email = input("Enter your email: ").strip()
    users = read_csv()
    login_attempts = 0
    
    for user in users:
        if user['email'] == email:
            while login_attempts < MAX_LOGIN_ATTEMPTS:
                password = input("Enter your password: ").strip()
                if check_password(user['hashed_password'].encode('utf-8'), password):
                    print("Login successful!")
                    return True
                else:
                    login_attempts += 1
                    print(f"Invalid password. You have {MAX_LOGIN_ATTEMPTS - login_attempts} attempts remaining.")
            print("Max login attempts reached. Try again later.")
            return False
    print("Email not found. Please register first.")
    return False


def forgot_password():
    email = input("Enter your registered email: ").strip()
    users = read_csv()
    
    for user in users:
        if user['email'] == email:
            print(f"Security question: {user['security_question']}")
            security_answer = input("Answer the security question: ").strip()
            
            if security_answer == user['security_answer']:
                while True:
                    new_password = input("Enter a new password: ").strip()
                    if password_validation(new_password):
                        break
                    else:
                        print("Password must meet validation criteria.")
                
                user['hashed_password'] = hash_password(new_password).decode('utf-8')
                write_csv(users)
                print("Password reset successful!")
                return
            else:
                print("Incorrect answer to the security question.")
                return
    print("Email not found.")


def search_books_menu():
    while True:
        display_menu()
        choice = input("Enter your choice: ").strip()
        
        if choice == '1':
            search_query = input("Enter book title: ").strip()
            search_books('title', search_query)
        elif choice == '2':
            search_query = input("Enter author name: ").strip()
            search_books('author', search_query)
        elif choice == '3':
            search_query = input("Enter ISBN: ").strip()
            search_books('isbn', search_query)
        elif choice == '4':
            print("Logging out...")
            return
        else:
            print("Invalid choice. Please try again.")


def search_books(search_type, search_query):
    try:
        response = requests.get(OPENLIBRARY_API_URL, params={search_type: search_query})
        response.raise_for_status()  
        books = response.json().get('docs', [])
        
        if not books:
            print(f"No books found for the {search_type}: {search_query}")
            return

        
        print("\nTop 5 search results:\n")
        for i, book in enumerate(books[:5], 1):
            title = book.get('title', 'N/A')
            author = ', '.join(book.get('author_name', ['N/A'])) if 'author_name' in book else 'N/A'
            year = book.get('first_publish_year', 'N/A')
            isbn = ', '.join(book.get('isbn', ['N/A'])) if 'isbn' in book else 'N/A'
            print(f"Result {i}:")
            print(f"  Title: {title}")
            print(f"  Author(s): {author}")
            print(f"  First Published Year: {year}")
            print(f"  ISBN: {isbn}\n")

    except requests.RequestException as e:
        print(f"Error connecting to OpenLibrary API: {e}")


def display_menu():
    print("\nBook Search Menu:")
    print("1. Search for a book by title")
    print("2. Search for a book by author")
    print("3. Search for a book by ISBN")
    print("4. Log out")


def main():
    print("Welcome to the Book Search Application!")
    
    while True:
        print("\n1. Register\n2. Login\n3. Forgot Password\n4. Exit")
        choice = input("Choose an option: ").strip()
        
        if choice == '1':
            register_user()
        elif choice == '2':
            if login_user():
                search_books_menu()
        elif choice == '3':
            forgot_password()
        elif choice == '4':
            print("Exiting the application.")
            sys.exit()
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
