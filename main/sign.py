import smtplib
import ssl
import os
import base64
from dotenv import load_dotenv
from Crypto import Random
import base64
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


length = 1024 # Length of RSA key
load_dotenv() # Load environment from .env file

# Try to load the public key from a file
try:
    with open('public_key.pem', 'rb') as f: # Opening the file in binary read mode
        public_key = RSA.import_key(f.read()) # Importing the RSA public key from the file
except (ValueError, FileNotFoundError) as e:  # Handling possible errors
    print(f"Error loading public key: {e}")  # Printing error message
    public_key = None # None to public key if loading fails

# Try to load the private key from a file
try:
    with open('private_key.pem', 'rb') as f: # Opening the file in binary read mode
        private_key = RSA.import_key(f.read())  # Importing the RSA private key from the file
except (ValueError, FileNotFoundError) as e: # Handling possible errors
    print(f"Error loading private key: {e}") # Printing error message
    private_key = None # None to public key if loading fails

# Function: load the private key from a file
def load_private_key():
    try: 
        with open('private_key.pem', 'rb') as f:
            private_key = RSA.import_key(f.read())
        return private_key # Returning the loaded private key
    except (ValueError, FileNotFoundError) as e:
        print(f"Error loading private key: {e}")
        return None # Returning None if loading fails

# Function: Generate RSA key pair
def genkey():
    private_key = RSA.generate(length, Random.new().read) # Generating a new RSA private key
    public_key = private_key.publickey() # Extract public key from generated private key
     # Saving the private key
    with open("./private_key.pem", "wb") as pub_file:
        pub_file.write(private_key.exportKey())
    # Saving the public key 
    with open("./public_key.pem", "wb") as pri_file:
        pri_file.write(public_key.exportKey())

#Function: Sign a message using a private key
def sign_message(message, private_key):
    signer = PKCS1_v1_5.new(private_key) # Creating a signer object with the private key
    digest = SHA256.new() # Create a SHA256 hash object
    digest.update(message.encode()) # Updating the hash with the message
    signature = signer.sign(digest) # Generating the signature
    return base64.b64encode(signature).decode() # Encoding the signature in base64 and returning it as a string

# # Function: Verify a signature using a public key
# def verify_signature(public_key, data, signature):
#     verifier = PKCS1_v1_5.new(public_key) # Creating a verifier object with the public key
#     digest = SHA256.new() # Create a SHA256 hash object
#     digest.update(data.encode()) # Updating the hash with the data
#     signature = base64.b64decode(signature) # Decoding the signature from base64
#     return verifier.verify(digest, signature) # Verifying the signature by returning True or False

# Function to send an email with a signature message
def send(receiver, subject, body):
    private_key = load_private_key() # Loading the private key
    if not private_key: # Checking if the private key is loaded successfully
        print("Private key not loaded. Unable to send email.")
        return
    signature = sign_message(body, private_key) # Signing the message with the private key
    # Email content with the signature
    message = f"{body}\n\n" # Creating the email message
    message += f"Signature: {signature}" # Adding the signature to the message

# Send the email
    port = 465  # Port for SSL connection
    smtp_server = "smtp.gmail.com" # SMTP server address
    sender_email = os.getenv("sender_email") # Sender's email address
    sender_password = os.getenv("sender_password") # Sender's email password

    context = ssl.create_default_context() # Creating a default SSL context
    try: # Trying to send the email
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server: #SSL connection to the SMTP server
            server.login(sender_email, sender_password) # Logging in to the SMTP server
            server.sendmail(sender_email, receiver, message) # Sending the email
        print("Email sent successfully!")
    except Exception as e: # Handling possible errors
        print(f"Error sending email: {e}")

# Function: Receive data and verify its signature
def receive(data, signature):
    # Load the public key (for verification)
    with open("public_key.pem", "rb") as key_file: # Opening the public key file in binary read mode
        public_key = RSA.import_key(key_file.read()) # Importing the RSA public key from the file

    # Load the private key (for expected signature calculation)
    with open("private_key.pem", "rb") as key_file:  # Opening the private key file in binary read mode
        private_key = RSA.import_key(key_file.read()) # Importing the RSA private key from the file

#Verify a signature using a public key
    # Initialize the signature verifier
    verifier = PKCS1_v1_5.new(public_key) # Creating a verifier object with the public key
    # Calculate the digest of the data
    digest = SHA256.new() # Creating a SHA256 hash object
    digest.update(data.encode()) # Updating the hash with the data
    # Decode the provided signature from base64
    provided_signature = base64.b64decode(signature)
    # Verify the signature
    if verifier.verify(digest, provided_signature):
        return "Signature is valid." # Returning a success message if the signature is valid
    else:
        # Calculate the expected signature using the private key
        signer = PKCS1_v1_5.new(private_key)  # Creating a signer object with the private key
        expected_signature = base64.b64encode(signer.sign(digest)).decode() # Calculating the expected signature
        print(f"Expected Signature: {expected_signature}") # Printing the expected signature (for debugging purposes)
        return "Signature verification failed." # Returning an error message if the signature is invalid
    