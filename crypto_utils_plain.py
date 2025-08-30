# crypto_utils_plain.py
# Unencrypted version for network traffic analysis with Wireshark

import os
import json
import base64

class User:
    """
    Represents a user without cryptography - only stores names.
    Maintains the same interface as the encrypted version for compatibility.
    """
    def __init__(self, name):
        self.name = name
        self.private_key = None  # Not used but kept for compatibility
        self.public_key = None  # Not used but kept for compatibility
        self.recipient_public_key = None
        self.recipient_name = "Other User"
        
        print(f"[INFO] User {name} created (unencrypted mode)")

    def generate_new_keys(self):
        """Dummy method - does not generate real keys."""
        print(f"[INFO] Keys 'generated' for {self.name} (dummy mode)")

    def save_keys(self):
        """Dummy method - simulates key saving."""
        print(f"[INFO] Keys for {self.name} 'saved' (dummy mode)")
        return True

    def load_keys(self):
        """Dummy method - simulates key loading."""
        print(f"[INFO] Keys for {self.name} 'loaded' (dummy mode)")
        return True

    def regenerate_keys(self):
        """Dummy method - simulates key regeneration."""
        print(f"[INFO] Keys for {self.name} 'regenerated' (dummy mode)")
        return True

    def serialize_public_key(self):
        """Returns a dummy public key in PEM format."""
        dummy_key = f"-----BEGIN PUBLIC KEY-----\nDUMMY_PUBLIC_KEY_FOR_{self.name}_PLAIN_MODE\n-----END PUBLIC KEY-----"
        return dummy_key.encode('utf-8')

    def serialize_private_key(self, password: str | None = None):
        """Returns a dummy private key in PEM format."""
        dummy_key = f"-----BEGIN PRIVATE KEY-----\nDUMMY_PRIVATE_KEY_FOR_{self.name}_PLAIN_MODE\n-----END PRIVATE KEY-----"
        return dummy_key.encode('utf-8')

def load_public_key(pem_data):
    """Dummy function that simulates loading a public key."""
    return "DUMMY_PUBLIC_KEY_OBJECT"

def encrypt_message(message, recipient_public_key, sender_private_key):
    """
    UNENCRYPTED VERSION: Returns the message in plain text within a JSON.
    
    This function maintains the same interface as the encrypted version but
    simply packages the message in JSON without applying any encryption.
    """
    # Create a simple JSON package with the message in plain text
    package = {
        "version": 1,
        "encryption": "NONE",
        "message_type": "PLAIN_TEXT",
        "plain_message": message,  # Message completely visible
        "timestamp": str(os.urandom(4).hex()),  # Dummy data for analysis
        "dummy_signature": "NO_SIGNATURE_PLAIN_MODE"
    }
    
    # Convert to JSON - this is what will travel over the network UNENCRYPTED
    json_message = json.dumps(package, indent=2)  # indent for better readability in Wireshark
    
    print(f"[DEBUG PLAIN] Message sent unencrypted: {message}")
    return json_message

def decrypt_message(package_json, recipient_private_key, sender_public_key):
    """
    UNENCRYPTED VERSION: Extracts the message in plain text from JSON.
    
    This function maintains the same interface as the encrypted version but
    simply extracts the message from JSON without applying any decryption.
    """
    try:
        package = json.loads(package_json)
        
        # Verify that it's a package from the unencrypted version
        if package.get("encryption") != "NONE":
            raise ValueError("Package is not from the unencrypted version")
        
        # Extract the message in plain text
        plain_message = package.get("plain_message", "")
        
        print(f"[DEBUG PLAIN] Message received unencrypted: {plain_message}")
        return plain_message
        
    except json.JSONDecodeError:
        raise ValueError("Malformed JSON in unencrypted message")
    except Exception as e:
        raise ValueError(f"Error processing unencrypted message: {e}")

def _debug_packet_info(package_json):
    """Utility function to show packet information for debugging."""
    try:
        package = json.loads(package_json)
        print(f"[PACKET DEBUG] Type: {package.get('message_type', 'UNKNOWN')}")
        print(f"[PACKET DEBUG] Encryption: {package.get('encryption', 'UNKNOWN')}")
        print(f"[PACKET DEBUG] Size: {len(package_json)} bytes")
        return True
    except:
        return False
