"""
CITS2006 Lab Quiz - Digital Signature and Certificate Chain
============================================================
Task 1: Single-User Digital Signature and Verification
Task 2: Certificate Chain Challenge

Usage:
    python3 lab_quiz.py

Replace STUDENT_ID and MESSAGE_PREFIX with your actual values.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import os

# ============================================================
# CONFIGURATION - CHANGE THESE BEFORE RUNNING
# ============================================================
STUDENT_ID = "12345678"          # <-- Replace with your 8-digit student ID
MESSAGE_PREFIX = "xxx"           # <-- Replace with the message given in the lab
MESSAGE = f"{MESSAGE_PREFIX}-{STUDENT_ID}"

# ============================================================
# TASK 1: Single-User Digital Signature and Verification
# ============================================================

def generate_keys():
    """
    Generate an RSA private/public key pair (2048-bit).
    Saves the private key to 'private_key.pem' and the public key to 'public_key.pem'.
    Returns the private key object.
    """
    # Generate a 2048-bit RSA private key using the default backend
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Save private key to PEM file (no encryption for simplicity)
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Extract the public key from the private key
    public_key = private_key.public_key()

    # Save public key to PEM file
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[Task 1] Keys generated and saved to 'private_key.pem' and 'public_key.pem'")
    return private_key


def sign_message(private_key, message):
    """
    Sign a message using the RSA private key with PSS padding and SHA-256 hash.
    Saves the signature to 'signature.bin'.
    Returns the signature bytes.
    """
    # Sign the message using PSS padding (Probabilistic Signature Scheme)
    signature = private_key.sign(
        message.encode('utf-8'),          # Convert string message to bytes
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),  # Mask Generation Function using SHA-256
            salt_length=padding.PSS.MAX_LENGTH   # Maximum salt length for security
        ),
        hashes.SHA256()                    # Hash algorithm used for signing
    )

    # Save signature to binary file
    with open("signature.bin", "wb") as f:
        f.write(signature)

    print(f"[Task 1] Message signed and saved to 'signature.bin'")
    return signature


def verify_signature(public_key, message, signature):
    """
    Verify a signature against a message using the RSA public key.
    Returns True if valid, False otherwise.
    """
    try:
        # Verify the signature using PSS padding (must match signing parameters)
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # Signature is valid
    except Exception:
        return False  # Signature is invalid (tampered or wrong key)


# ============================================================
# TASK 2: Certificate Chain Challenge
# ============================================================

def generate_ca_keys():
    """
    Generate an RSA key pair for the Certificate Authority (CA).
    Saves CA keys to 'ca_private_key.pem' and 'ca_public_key.pem'.
    Returns the CA private key object.
    """
    # Generate a 2048-bit RSA private key for the CA
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Save CA private key to PEM file
    with open("ca_private_key.pem", "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save CA public key to PEM file
    ca_public_key = ca_private_key.public_key()
    with open("ca_public_key.pem", "wb") as f:
        f.write(ca_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[Task 2] CA keys generated and saved to 'ca_private_key.pem' and 'ca_public_key.pem'")
    return ca_private_key


def create_certificate(student_id, public_key):
    """
    Create a certificate binding the student ID (last 4 digits) to their public key.
    The certificate contains: student_id_last4 | public_exponent | modulus
    Returns the serialized certificate as bytes.
    """
    # Extract the public key numbers (e = public exponent, n = modulus)
    pub_numbers = public_key.public_numbers()
    e = pub_numbers.e  # Public exponent (typically 65537)
    n = pub_numbers.n  # Modulus (large number unique to this key pair)

    # Use last 4 digits of student ID as specified
    last_four = student_id[-4:]

    # Serialize certificate as byte string: "last4digits|exponent|modulus"
    cert_data = f"{last_four}|{e}|{n}".encode('utf-8')

    print(f"[Task 2] Certificate created for student ID ending in '{last_four}'")
    return cert_data


def sign_certificate(ca_private_key, cert_data):
    """
    Sign the certificate data with the CA's private key.
    This produces the CA's endorsement of the student's certificate.
    Saves the certificate signature to 'ca_cert_signature.bin'.
    Returns the signature bytes.
    """
    # CA signs the certificate using PSS padding and SHA-256
    cert_signature = ca_private_key.sign(
        cert_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Save CA certificate signature to binary file
    with open("ca_cert_signature.bin", "wb") as f:
        f.write(cert_signature)

    print("[Task 2] Certificate signed by CA and saved to 'ca_cert_signature.bin'")
    return cert_signature


def verify_certificate(ca_public_key, cert_data, cert_signature):
    """
    Verify the CA's signature on the certificate data.
    This confirms the certificate was genuinely issued by the CA.
    Returns True if valid, False otherwise.
    """
    try:
        ca_public_key.verify(
            cert_signature,
            cert_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # Certificate is authentic
    except Exception:
        return False  # Certificate is forged or tampered


def pubkey_from_cert(cert_data):
    """
    Reconstruct the student's RSA public key from the certificate data.
    Parses the 'id|e|n' format and rebuilds the public key object.
    Returns the reconstructed RSA public key.
    """
    # Decode and split the certificate data
    parts = cert_data.decode('utf-8').split('|')
    # parts[0] = student ID (last 4 digits)
    # parts[1] = public exponent (e)
    # parts[2] = modulus (n)
    e = int(parts[1])
    n = int(parts[2])

    # Reconstruct the public key from e and n
    public_numbers = rsa.RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key(default_backend())

    print(f"[Task 2] Public key reconstructed from certificate (student ID: {parts[0]})")
    return public_key


# ============================================================
# MAIN - RUN ALL TASKS AND TESTS
# ============================================================

def main():
    print("=" * 60)
    print("CITS2006 Lab Quiz - Digital Signature & Certificate Chain")
    print("=" * 60)
    print(f"Student ID: {STUDENT_ID}")
    print(f"Message:    {MESSAGE}")
    print()

    # ----------------------------------------------------------
    # TASK 1: Digital Signature
    # ----------------------------------------------------------
    print("-" * 60)
    print("TASK 1: Single-User Digital Signature and Verification")
    print("-" * 60)

    # Step 1 & 2: Generate RSA key pair
    private_key = generate_keys()
    public_key = private_key.public_key()

    # Step 3: Sign the message
    signature = sign_message(private_key, MESSAGE)

    # Print signature in hexadecimal
    print(f"\nSignature (hex): {signature.hex()}")

    # Step 4: Verify the signature (should be True)
    is_valid = verify_signature(public_key, MESSAGE, signature)
    print(f"\nVerification of original message: {is_valid}")  # Expected: True

    # Step 4 (continued): Modify message and show verification fails
    tampered_message = f"{MESSAGE_PREFIX}-00000000"
    is_valid_tampered = verify_signature(public_key, tampered_message, signature)
    print(f"Verification of tampered message: {is_valid_tampered}")  # Expected: False

    print()

    # ----------------------------------------------------------
    # TASK 2: Certificate Chain
    # ----------------------------------------------------------
    print("-" * 60)
    print("TASK 2: Certificate Chain Challenge")
    print("-" * 60)

    # Step 5: Generate CA key pair
    ca_private_key = generate_ca_keys()
    ca_public_key = ca_private_key.public_key()

    # Step 6: Create certificate binding student ID to public key
    cert_data = create_certificate(STUDENT_ID, public_key)
    print(f"\nCertificate data: {cert_data.decode('utf-8')[:80]}...")

    # Step 7: CA signs the certificate
    cert_signature = sign_certificate(ca_private_key, cert_data)

    # Step 8: Sign the message with student's private key (reuse from Task 1)
    message_signature = sign_message(private_key, MESSAGE)

    # Step 9: Verify the certificate using CA's public key
    print("\n--- Verification Chain ---")
    cert_valid = verify_certificate(ca_public_key, cert_data, cert_signature)
    print(f"Certificate verification: {cert_valid}")  # Expected: True

    if cert_valid:
        # Step 10: Extract public key from certificate and verify message
        extracted_pubkey = pubkey_from_cert(cert_data)
        msg_valid = verify_signature(extracted_pubkey, MESSAGE, message_signature)
        print(f"Message signature verification: {msg_valid}")  # Expected: True
    else:
        print("Certificate INVALID - rejecting message signature without checking.")

    # ----------------------------------------------------------
    # ADDITIONAL TESTS: Tamper detection
    # ----------------------------------------------------------
    print("\n--- Tamper Detection Tests ---")

    # Test: Tampered certificate (changed student ID)
    tampered_cert = cert_data.replace(STUDENT_ID[-4:].encode(), b"0000")
    tampered_cert_valid = verify_certificate(ca_public_key, tampered_cert, cert_signature)
    print(f"Tampered certificate verification: {tampered_cert_valid}")  # Expected: False

    # Test: Wrong CA key (attacker's key)
    fake_ca_key = rsa.generate_private_key(65537, 2048, default_backend())
    fake_cert_valid = verify_certificate(fake_ca_key.public_key(), cert_data, cert_signature)
    print(f"Wrong CA key verification: {fake_cert_valid}")  # Expected: False

    # Test: Valid cert but tampered message
    if cert_valid:
        tampered_msg_valid = verify_signature(extracted_pubkey, "TAMPERED-99999999", message_signature)
        print(f"Tampered message verification: {tampered_msg_valid}")  # Expected: False

    # ----------------------------------------------------------
    # SUMMARY OF FILES GENERATED
    # ----------------------------------------------------------
    print("\n" + "=" * 60)
    print("FILES GENERATED (upload these to the server):")
    print("=" * 60)
    files = [
        "private_key.pem",
        "public_key.pem",
        "signature.bin",
        "ca_private_key.pem",
        "ca_public_key.pem",
        "ca_cert_signature.bin",
    ]
    for f in files:
        size = os.path.getsize(f) if os.path.exists(f) else "NOT FOUND"
        print(f"  {f:30s}  ({size} bytes)")


if __name__ == "__main__":
    main()
