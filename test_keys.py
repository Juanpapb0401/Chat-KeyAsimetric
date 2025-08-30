#!/usr/bin/env python3
"""
Test script to demonstrate the key persistence system.
This script creates users, generates keys, saves them, loads them and regenerates them.
"""

import os
import shutil
from crypto_utils import User

def clean_keys_directory():
    """Cleans the keys directory for testing."""
    if os.path.exists("keys"):
        shutil.rmtree("keys")
        print("[INFO] 'keys' directory removed for clean testing.")

def show_keys_status(name):
    """Shows the status of keys for a user."""
    keys_dir = "keys"
    priv_key_file = os.path.join(keys_dir, f"{name}_private.key")
    pub_key_file = os.path.join(keys_dir, f"{name}_public.key")
    
    print(f"\n----- KEY STATUS FOR {name.upper()} -----")
    print(f"Keys directory: {os.path.abspath(keys_dir)}")
    print(f"Private key: {'✓ Exists' if os.path.exists(priv_key_file) else '✗ Does not exist'}")
    print(f"Public key: {'✓ Exists' if os.path.exists(pub_key_file) else '✗ Does not exist'}")
    
    if os.path.exists(priv_key_file):
        file_size = os.path.getsize(priv_key_file)
        print(f"Private file size: {file_size} bytes")
    if os.path.exists(pub_key_file):
        file_size = os.path.getsize(pub_key_file)
        print(f"Public file size: {file_size} bytes")

def test_key_persistence():
    """Complete test of the key persistence system."""
    print("=== KEY PERSISTENCE SYSTEM TEST ===\n")
    
    # Clean directory for testing
    clean_keys_directory()
    
    print("1. CREATING USER ALICE (first time - generates keys)")
    alice1 = User("Alice")
    print(f"   - Private key generated: {'✓' if alice1.private_key else '✗'}")
    print(f"   - Public key generated: {'✓' if alice1.public_key else '✗'}")
    
    # Save Alice's keys
    alice1.save_keys()
    show_keys_status("Alice")
    
    print("\n2. CREATING USER BOB (first time - generates keys)")
    bob1 = User("Bob")
    print(f"   - Private key generated: {'✓' if bob1.private_key else '✗'}")
    print(f"   - Public key generated: {'✓' if bob1.public_key else '✗'}")
    
    # Save Bob's keys
    bob1.save_keys()
    show_keys_status("Bob")
    
    print("\n3. RECREATING USER ALICE (second time - loads existing keys)")
    alice2 = User("Alice")
    print(f"   - Private key loaded: {'✓' if alice2.private_key else '✗'}")
    print(f"   - Public key loaded: {'✓' if alice2.public_key else '✗'}")
    
    print("\n4. RECREATING USER BOB (second time - loads existing keys)")
    bob2 = User("Bob")
    print(f"   - Private key loaded: {'✓' if bob2.private_key else '✗'}")
    print(f"   - Public key loaded: {'✓' if bob2.public_key else '✗'}")
    
    print("\n5. VERIFYING THAT KEYS ARE THE SAME")
    # Compare public keys (easier to verify)
    alice_pub1 = alice1.serialize_public_key()
    alice_pub2 = alice2.serialize_public_key()
    bob_pub1 = bob1.serialize_public_key()
    bob_pub2 = bob2.serialize_public_key()
    
    print(f"   - Alice: {'✓ Same keys' if alice_pub1 == alice_pub2 else '✗ Different keys'}")
    print(f"   - Bob: {'✓ Same keys' if bob_pub1 == bob_pub2 else '✗ Different keys'}")
    
    print("\n6. REGENERATING ALICE'S KEYS")
    alice2.regenerate_keys()
    show_keys_status("Alice")
    
    print("\n7. VERIFYING THAT NEW KEYS ARE DIFFERENT")
    alice_pub3 = alice2.serialize_public_key()
    print(f"   - Alice: {'✓ Different keys' if alice_pub1 != alice_pub3 else '✗ Same keys'}")
    
    print("\n=== TEST COMPLETED ===")
    print("\nTo test the complete chat:")
    print("1. Run: python server.py")
    print("2. In another terminal: python client.py Alice")
    print("3. In another terminal: python client.py Bob")
    print("\nAvailable commands in chat:")
    print("- /showkeys: View your keys")
    print("- /regenerate: Regenerate keys")
    print("- /keyinfo: Key information")
    print("- /exit: Exit")

if __name__ == "__main__":
    test_key_persistence() 