import os
import base64
import shutil
import cryptography
import time
import logging
import hashlib
from PIL import Image

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

def sign_image(image_path):
    start_time = time.time()
    logger.info("Signing the image with OAEP padding and SHA-256 hashing algorithm...")

    # Load the private key
    with open('private.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Load the contents of the image to be signed
    with open(image_path, 'rb') as image_file:
        image_contents = image_file.read()

    # Calculate the hash of the image
    image_hash = hashlib.sha256(image_contents).digest()

    # Sign the image hash
    signature = private_key.sign(
        image_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),  # Use OAEP padding with SHA-256
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256()
    )

    # Save the signature to a file
    signature_filename = os.path.splitext(os.path.basename(image_path))[0] + '.sig'
    with open(signature_filename, 'wb') as signature_file:
        signature_file.write(base64.b64encode(signature))

    # Save the hash to a file
    hash_filename = os.path.splitext(os.path.basename(image_path))[0] + '.hash'
    with open(hash_filename, 'wb') as hash_file:
        hash_file.write(image_hash)
    
    end_time = time.time()
    logger.info(f"Image Signing Time: {end_time - start_time} seconds")

def verify_image(image_path):
    start_time = time.time()
    logger.info("Verifying the image...")

    # Load the public key
    with open('public.pem', 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), default_backend())

    # Load the contents of the image
    with open(image_path, 'rb') as image_file:
        image_contents = image_file.read()

    # Calculate the hash of the image
    image_hash = hashlib.sha256(image_contents).digest()

    # Get the signature filename
    signature_filename = os.path.splitext(os.path.basename(image_path))[0] + '.sig'
    hash_filename = os.path.splitext(os.path.basename(image_path))[0] + '.hash'

    # Check if the signature file exists
    if not os.path.exists(signature_filename):
        logger.error(f"No signature file found for {image_path}!")
        return

    # Load the signature
    with open(signature_filename, 'rb') as signature_file:
        signature = base64.b64decode(signature_file.read())

    # Load the stored hash
    with open(hash_filename, 'rb') as hash_file:
        stored_hash = hash_file.read()

    # Perform the verification
    try:
        public_key.verify(
            signature,
            image_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),  # Use OAEP padding with SHA-256
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        logger.info('Verification is done successfully!')
        
        # Compare the hash of the image with the stored hash
        if stored_hash == image_hash:
            
            # Prompt user to check against original image file
            check_original = input("Do you want to compare with the original image file? (yes/no): ").lower()
            if check_original == 'yes':
                original_image_path = input("Enter the path of the original image file: ")
                with open(original_image_path, 'rb') as original_image_file:
                    original_image_contents = original_image_file.read()
                original_image_hash = hashlib.sha256(original_image_contents).digest()
                if original_image_hash == image_hash:
                    logger.info("The contents of the signed image match the original image file.")
                else:
                    logger.warning("WARNING: The contents of the signed image do not match the original image file.")
    except Exception as e:
        logger.error('ERROR: Image signature verification failed!')
    
    end_time = time.time()
    logger.info(f"Image Verification Time: {end_time - start_time} seconds")

# Main function
if __name__ == "__main__":
    logger = logging.getLogger(__name__)

    # Generate keys
    generate_keys()

    while True:
        # Prompt user for the image path
        image_path = input("Enter the path of the image file (JPEG or PNG): ")

        # Sign the image
        sign_image(image_path)

        # Verify the image
        verify_image(image_path)

        # Ask user if they want to check another image
        check_another = input("Do you want to check another image? (yes/no): ").lower()
        if check_another != 'yes':
            break