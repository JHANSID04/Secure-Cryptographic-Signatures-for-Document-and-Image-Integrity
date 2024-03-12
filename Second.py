import os
import base64
import PyPDF2
import shutil
import cryptography
import time
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Configure logging
logging.basicConfig(level=logging.INFO)

# Key Generation
def generate_keys():
    start_time = time.time()
    logger.info("Generating RSA keys with increased key size (4096 bits)...")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,  # Increased key size
        backend=default_backend()
    )

    # Generate public key
    public_key = private_key.public_key()

    # Save the private key to a file
    with open("private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save the public key to a file
    with open("public.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    
    end_time = time.time()
    logger.info(f"Key Generation Time: {end_time - start_time} seconds")

def sign_pdf():
    start_time = time.time()
    logger.info("Signing the PDF with OAEP padding and SHA-256 hashing algorithm...")

    # Load the private key
    with open('private.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Prompt user for the initial file path
    input_file_path = input("Enter the path of the file to sign (initial file): ")
    
    # Load the contents of the file to be signed
    with open(input_file_path, 'rb') as pdf_file:
        pdf_contents = pdf_file.read()

    # Sign the PDF contents
    signature = private_key.sign(
        pdf_contents,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),  # Use OAEP padding with SHA-256
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256()
    )

    # Save the signature to a file
    with open('signature.sig', 'wb') as signature_file:
        signature_file.write(base64.b64encode(signature))
    
    end_time = time.time()
    logger.info(f"PDF Signing Time: {end_time - start_time} seconds")

def verify_pdf():
    start_time = time.time()
    logger.info("Verifying the PDF and checking contents...")

    # Load the public key
    with open('public.pem', 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), default_backend())

    # Prompt user for the end file path after verification
    end_file_path = input("Enter the path of the file to verify and check (end file): ")

    # Load the contents of the PDF file and the signature
    with open(end_file_path, 'rb') as pdf_file:
        pdf_contents = pdf_file.read()
    with open('signature.sig', 'rb') as signature_file:
        signature_bytes = base64.b64decode(signature_file.read())

    # Perform the verification
    try:
        public_key.verify(
            signature_bytes,
            pdf_contents,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),  # Use OAEP padding with SHA-256
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        logger.info('Verification is done successfully!')
        
        # If verification is successful, read and display the contents of the PDF file
        pdf_reader = PyPDF2.PdfReader(end_file_path)
        for page in pdf_reader.pages:
            print(page.extract_text())

        # Check if the file contents match the originally signed file
        input_file_path = input("Enter the path of the initial file to check its contents against the signed PDF: ")

        with open(input_file_path, 'rb') as check_file:
            check_contents = check_file.read()

        if check_contents == pdf_contents:
            logger.info("The contents of the files match.")
        else:
            logger.info("The contents of the files do not match.")

    except cryptography.exceptions.InvalidSignature as e:
        logger.error('ERROR: PDF file content and/or signature files failed verification!')
    
    end_time = time.time()
    logger.info(f"PDF Verification and Check Time: {end_time - start_time} seconds")

# Main function
if __name__ == "__main__":
    logger = logging.getLogger(__name__)

    # Generate keys
    generate_keys()

    # Sign the PDF
    sign_pdf()

    # Verify the PDF and check contents
    verify_pdf()
