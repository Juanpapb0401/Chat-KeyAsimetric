#!/usr/bin/env python3
"""
Script de prueba para demostrar el sistema de persistencia de llaves.
Este script crea usuarios, genera llaves, las guarda, las carga y las regenera.
"""

import os
import shutil
from cripto_utils import Usuario

def limpiar_directorio_keys():
    """Limpia el directorio de llaves para pruebas."""
    if os.path.exists("keys"):
        shutil.rmtree("keys")
        print("[INFO] Directorio 'keys' eliminado para pruebas limpias.")

def mostrar_estado_llaves(nombre):
    """Muestra el estado de las llaves para un usuario."""
    keys_dir = "keys"
    priv_key_file = os.path.join(keys_dir, f"{nombre}_private.key")
    pub_key_file = os.path.join(keys_dir, f"{nombre}_public.key")
    
    print(f"\n----- ESTADO DE LLAVES PARA {nombre.upper()} -----")
    print(f"Directorio de llaves: {os.path.abspath(keys_dir)}")
    print(f"Llave privada: {'✓ Existe' if os.path.exists(priv_key_file) else '✗ No existe'}")
    print(f"Llave pública: {'✓ Existe' if os.path.exists(pub_key_file) else '✗ No existe'}")
    
    if os.path.exists(priv_key_file):
        file_size = os.path.getsize(priv_key_file)
        print(f"Tamaño archivo privado: {file_size} bytes")
    if os.path.exists(pub_key_file):
        file_size = os.path.getsize(pub_key_file)
        print(f"Tamaño archivo público: {file_size} bytes")

def test_persistencia_llaves():
    """Prueba completa del sistema de persistencia de llaves."""
    print("=== PRUEBA DEL SISTEMA DE PERSISTENCIA DE LLAVES ===\n")
    
    # Limpiar directorio para pruebas
    limpiar_directorio_keys()
    
    print("1. CREANDO USUARIO ALICE (primera vez - genera llaves)")
    alice1 = Usuario("Alice")
    print(f"   - Clave privada generada: {'✓' if alice1.clave_privada else '✗'}")
    print(f"   - Clave pública generada: {'✓' if alice1.clave_publica else '✗'}")
    
    # Guardar llaves de Alice
    alice1.guardar_llaves()
    mostrar_estado_llaves("Alice")
    
    print("\n2. CREANDO USUARIO BOB (primera vez - genera llaves)")
    bob1 = Usuario("Bob")
    print(f"   - Clave privada generada: {'✓' if bob1.clave_privada else '✗'}")
    print(f"   - Clave pública generada: {'✓' if bob1.clave_publica else '✗'}")
    
    # Guardar llaves de Bob
    bob1.guardar_llaves()
    mostrar_estado_llaves("Bob")
    
    print("\n3. RECREANDO USUARIO ALICE (segunda vez - carga llaves existentes)")
    alice2 = Usuario("Alice")
    print(f"   - Clave privada cargada: {'✓' if alice2.clave_privada else '✗'}")
    print(f"   - Clave pública cargada: {'✓' if alice2.clave_publica else '✗'}")
    
    print("\n4. RECREANDO USUARIO BOB (segunda vez - carga llaves existentes)")
    bob2 = Usuario("Bob")
    print(f"   - Clave privada cargada: {'✓' if bob2.clave_privada else '✗'}")
    print(f"   - Clave pública cargada: {'✓' if bob2.clave_publica else '✗'}")
    
    print("\n5. VERIFICANDO QUE LAS LLAVES SEAN LAS MISMAS")
    # Comparar claves públicas (más fácil de verificar)
    alice_pub1 = alice1.serializar_clave_publica()
    alice_pub2 = alice2.serializar_clave_publica()
    bob_pub1 = bob1.serializar_clave_publica()
    bob_pub2 = bob2.serializar_clave_publica()
    
    print(f"   - Alice: {'✓ Mismas llaves' if alice_pub1 == alice_pub2 else '✗ Llaves diferentes'}")
    print(f"   - Bob: {'✓ Mismas llaves' if bob_pub1 == bob_pub2 else '✗ Llaves diferentes'}")
    
    print("\n6. REGENERANDO LLAVES DE ALICE")
    alice2.regenerar_llaves()
    mostrar_estado_llaves("Alice")
    
    print("\n7. VERIFICANDO QUE LAS NUEVAS LLAVES SEAN DIFERENTES")
    alice_pub3 = alice2.serializar_clave_publica()
    print(f"   - Alice: {'✓ Llaves diferentes' if alice_pub1 != alice_pub3 else '✗ Mismas llaves'}")
    
    print("\n=== PRUEBA COMPLETADA ===")
    print("\nPara probar el chat completo:")
    print("1. Ejecuta: python servidor.py")
    print("2. En otra terminal: python client.py Alice")
    print("3. En otra terminal: python client.py Bob")
    print("\nComandos disponibles en el chat:")
    print("- /showkeys: Ver tus llaves")
    print("- /regenerate: Regenerar llaves")
    print("- /keyinfo: Información de llaves")
    print("- /exit: Salir")

if __name__ == "__main__":
    test_persistencia_llaves() 