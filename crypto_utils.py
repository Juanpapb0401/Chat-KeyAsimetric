# crypto_utils.py

import os
import json
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class User:
    """
    Represents a user with their RSA key pair and name.
    """
    def __init__(self, name):
        self.name = name
        self.private_key = None
        self.public_key = None
        self.recipient_public_key = None
        self.recipient_name = "Other User"
        
        # Try to load existing keys, if they don't exist, generate new ones
        if not self.load_keys():
            self.generate_new_keys()
            self.save_keys()

    def generate_new_keys(self):
        """Generates a new RSA key pair."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

    def save_keys(self):
        """Saves keys in separate files in base64 format."""
        try:
            # Create keys directory if it doesn't exist
            keys_dir = "keys"
            if not os.path.exists(keys_dir):
                os.makedirs(keys_dir)
            
            # Serialize keys
            priv_key_pem = self.serialize_private_key()
            pub_key_pem = self.serialize_public_key()
            
            # Convert to base64
            priv_key_b64 = base64.b64encode(priv_key_pem).decode('utf-8')
            pub_key_b64 = base64.b64encode(pub_key_pem).decode('utf-8')
            
            # Save private key
            priv_key_file = os.path.join(keys_dir, f"{self.name}_private.key")
            with open(priv_key_file, 'w') as f:
                f.write(priv_key_b64)
            
            # Save public key
            pub_key_file = os.path.join(keys_dir, f"{self.name}_public.key")
            with open(pub_key_file, 'w') as f:
                f.write(pub_key_b64)
            
            print(f"[INFO] Keys for {self.name} saved successfully.")
            return True
            
        except Exception as e:
            print(f"[ERROR] Could not save keys for {self.name}: {e}")
            return False

    def load_keys(self):
        """Loads keys from files if they exist."""
        try:
            keys_dir = "keys"
            priv_key_file = os.path.join(keys_dir, f"{self.name}_private.key")
            pub_key_file = os.path.join(keys_dir, f"{self.name}_public.key")
            
            # Check if both files exist
            if not (os.path.exists(priv_key_file) and os.path.exists(pub_key_file)):
                print(f"[INFO] No existing keys found for {self.name}. New ones will be generated.")
                return False
            
            # Load private key
            with open(priv_key_file, 'r') as f:
                priv_key_b64 = f.read().strip()
            
            # Load public key
            with open(pub_key_file, 'r') as f:
                pub_key_b64 = f.read().strip()
            
            # Decode from base64
            priv_key_pem = base64.b64decode(priv_key_b64)
            pub_key_pem = base64.b64decode(pub_key_b64)
            
            # Load the keys
            self.private_key = serialization.load_pem_private_key(
                priv_key_pem, 
                password=None
            )
            self.public_key = serialization.load_pem_public_key(pub_key_pem)
            
            print(f"[INFO] Keys for {self.name} loaded successfully from files.")
            return True
            
        except Exception as e:
            print(f"[ERROR] Could not load keys for {self.name}: {e}")
            return False

    def regenerate_keys(self):
        """Forces key regeneration and saves them."""
        print(f"[INFO] Regenerating keys for {self.name}...")
        self.generate_new_keys()
        return self.save_keys()

    def serialize_public_key(self):
        """Converts the public key to bytes so it can be sent over the network."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def serialize_private_key(self, password: str | None = None):
        """Converts the private key to PEM bytes.

        If password is provided, it's encrypted with the best available option.
        Otherwise, it's returned unencrypted (for educational purposes only).
        """
        encryption_alg = (
            serialization.BestAvailableEncryption(password.encode('utf-8'))
            if password else serialization.NoEncryption()
        )
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_alg,
        )

def load_public_key(pem_data):
    """Loads a public key from its PEM bytes format."""
    return serialization.load_pem_public_key(pem_data)

def _canonical_json_bytes(obj):
    """Returns the canonical JSON representation in bytes for signing/verifying."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def encrypt_message(message, recipient_public_key, sender_private_key):
    """Encrypts and signs a message using a hybrid scheme and RSA-PSS.

    - Generates a random AES-256 key per message
    - Encrypts the message with AES-GCM (random nonce)
    - Wraps the AES key with the recipient's public key (RSA-OAEP)
    - Signs the canonical packet with the sender's private key (RSA-PSS)
    """
    # Random symmetric key per message
    symmetric_key = os.urandom(32)

    # Symmetric encryption
    aesgcm = AESGCM(symmetric_key)
    nonce = os.urandom(12)
    encrypted_message = aesgcm.encrypt(nonce, message.encode("utf-8"), None)

    # Wrap symmetric key with RSA-OAEP
    encrypted_symmetric_key = recipient_public_key.encrypt(
        symmetric_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Build base package (without signature)
    unsigned_package = {
        "version": 1,
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "encrypted_symmetric_key": base64.b64encode(encrypted_symmetric_key).decode("utf-8"),
        "encrypted_message": base64.b64encode(encrypted_message).decode("utf-8"),
    }

    # Sign canonical package
    data_to_sign = _canonical_json_bytes(unsigned_package)
    signature = sender_private_key.sign(
        data_to_sign,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    package = {**unsigned_package, "signature": base64.b64encode(signature).decode("utf-8")}
    return json.dumps(package)

def decrypt_message(package_json, recipient_private_key, sender_public_key):
    """Verifies signature and decrypts a received message as a JSON package."""
    package = json.loads(package_json)

    signature_b64 = package.get("signature")
    if not signature_b64:
        raise ValueError("Package without signature")

    # Reconstruct canonical object without signature for verification
    unsigned_package = {
        "version": package.get("version", 1),
        "nonce": package["nonce"],
        "encrypted_symmetric_key": package["encrypted_symmetric_key"],
        "encrypted_message": package["encrypted_message"],
    }

    data_to_verify = _canonical_json_bytes(unsigned_package)
    signature = base64.b64decode(signature_b64)

    # Verify signature (authenticity and integrity)
    sender_public_key.verify(
        signature,
        data_to_verify,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # Decode fields and decrypt
    nonce = base64.b64decode(package["nonce"])
    encrypted_symmetric_key = base64.b64decode(package["encrypted_symmetric_key"])
    encrypted_message = base64.b64decode(package["encrypted_message"])

    symmetric_key = recipient_private_key.decrypt(
        encrypted_symmetric_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aesgcm = AESGCM(symmetric_key)
    original_message_bytes = aesgcm.decrypt(nonce, encrypted_message, None)
    return original_message_bytes.decode("utf-8")

