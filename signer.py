import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_keys():
    """Generates a Private and Public key pair and saves them to files."""
    print("\n--- Generating New Keys ---")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Save Private Key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save Public Key
    public_key = private_key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print("✅ Keys saved as 'private_key.pem' and 'public_key.pem'")

def sign_file():
    """Signs a file using the private key."""
    filename = input("\nEnter the filename to sign (e.g., document.txt): ")
    
    if not os.path.exists(filename):
        print("❌ File not found!")
        return

    # Load Private Key
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    # Read file data
    with open(filename, "rb") as f:
        data = f.read()

    # Create Signature
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Save Signature
    sig_filename = filename + ".sig"
    with open(sig_filename, "wb") as f:
        f.write(signature)
    
    print(f"✅ File signed! Signature saved as '{sig_filename}'")

def verify_file():
    """Verifies a file signature using the public key."""
    filename = input("\nEnter the original filename (e.g., document.txt): ")
    sig_filename = input("Enter the signature filename (e.g., document.txt.sig): ")

    if not os.path.exists(filename) or not os.path.exists(sig_filename):
        print("❌ File or Signature not found!")
        return

    # Load Public Key
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Read file and signature
    with open(filename, "rb") as f:
        data = f.read()
    with open(sig_filename, "rb") as f:
        signature = f.read()

    # Verify
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("\n🟢 SUCCESS: The signature is VALID. The file has not been tampered with.")
    except Exception:
        print("\n🔴 DANGER: The signature is INVALID! The file may have been modified.")

def main():
    while True:
        print("\n=== RSA Digital Signer Tool ===")
        print("1. Generate Keys")
        print("2. Sign a File")
        print("3. Verify a Signature")
        print("4. Exit")
        choice = input("Select an option (1-4): ")

        if choice == '1':
            generate_keys()
        elif choice == '2':
            sign_file()
        elif choice == '3':
            verify_file()
        elif choice == '4':
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()