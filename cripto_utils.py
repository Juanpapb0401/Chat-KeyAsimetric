# crypto_utils.py

import os
import json
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Usuario:
    """
    Representa a un usuario con su par de claves RSA y su nombre.
    """
    def __init__(self, nombre):
        self.nombre = nombre
        self.clave_privada = None
        self.clave_publica = None
        self.clave_publica_destinatario = None
        self.nombre_destinatario = "Otro Usuario"
        
        # Intentar cargar llaves existentes, si no existen, generar nuevas
        if not self.cargar_llaves():
            self.generar_nuevas_llaves()
            self.guardar_llaves()

    def generar_nuevas_llaves(self):
        """Genera un nuevo par de llaves RSA."""
        self.clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.clave_publica = self.clave_privada.public_key()

    def guardar_llaves(self):
        """Guarda las llaves en archivos separados en formato base64."""
        try:
            # Crear directorio de llaves si no existe
            keys_dir = "keys"
            if not os.path.exists(keys_dir):
                os.makedirs(keys_dir)
            
            # Serializar llaves
            priv_key_pem = self.serializar_clave_privada()
            pub_key_pem = self.serializar_clave_publica()
            
            # Convertir a base64
            priv_key_b64 = base64.b64encode(priv_key_pem).decode('utf-8')
            pub_key_b64 = base64.b64encode(pub_key_pem).decode('utf-8')
            
            # Guardar llave privada
            priv_key_file = os.path.join(keys_dir, f"{self.nombre}_private.key")
            with open(priv_key_file, 'w') as f:
                f.write(priv_key_b64)
            
            # Guardar llave pública
            pub_key_file = os.path.join(keys_dir, f"{self.nombre}_public.key")
            with open(pub_key_file, 'w') as f:
                f.write(pub_key_b64)
            
            print(f"[INFO] Llaves de {self.nombre} guardadas exitosamente.")
            return True
            
        except Exception as e:
            print(f"[ERROR] No se pudieron guardar las llaves de {self.nombre}: {e}")
            return False

    def cargar_llaves(self):
        """Carga las llaves desde archivos si existen."""
        try:
            keys_dir = "keys"
            priv_key_file = os.path.join(keys_dir, f"{self.nombre}_private.key")
            pub_key_file = os.path.join(keys_dir, f"{self.nombre}_public.key")
            
            # Verificar si ambos archivos existen
            if not (os.path.exists(priv_key_file) and os.path.exists(pub_key_file)):
                print(f"[INFO] No se encontraron llaves existentes para {self.nombre}. Se generarán nuevas.")
                return False
            
            # Cargar llave privada
            with open(priv_key_file, 'r') as f:
                priv_key_b64 = f.read().strip()
            
            # Cargar llave pública
            with open(pub_key_file, 'r') as f:
                pub_key_b64 = f.read().strip()
            
            # Decodificar desde base64
            priv_key_pem = base64.b64decode(priv_key_b64)
            pub_key_pem = base64.b64decode(pub_key_b64)
            
            # Cargar las llaves
            self.clave_privada = serialization.load_pem_private_key(
                priv_key_pem, 
                password=None
            )
            self.clave_publica = serialization.load_pem_public_key(pub_key_pem)
            
            print(f"[INFO] Llaves de {self.nombre} cargadas exitosamente desde archivos.")
            return True
            
        except Exception as e:
            print(f"[ERROR] No se pudieron cargar las llaves de {self.nombre}: {e}")
            return False

    def regenerar_llaves(self):
        """Fuerza la regeneración de llaves y las guarda."""
        print(f"[INFO] Regenerando llaves para {self.nombre}...")
        self.generar_nuevas_llaves()
        return self.guardar_llaves()

    def serializar_clave_publica(self):
        """Convierte la clave pública a bytes para poder ser enviada por la red."""
        return self.clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def serializar_clave_privada(self, password: str | None = None):
        """Convierte la clave privada a bytes PEM.

        Si se proporciona password, se cifra con la mejor opción disponible.
        Caso contrario, se devuelve sin cifrar (solo para fines educativos).
        """
        encryption_alg = (
            serialization.BestAvailableEncryption(password.encode('utf-8'))
            if password else serialization.NoEncryption()
        )
        return self.clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_alg,
        )

def cargar_clave_publica(pem_data):
    """Carga una clave pública desde su formato de bytes PEM."""
    return serialization.load_pem_public_key(pem_data)

def _canonical_json_bytes(obj):
    """Devuelve la representación JSON canónica en bytes para firmar/verificar."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def encriptar_mensaje(mensaje, clave_publica_destinatario, clave_privada_emisor):
    """Encripta y firma un mensaje usando un esquema híbrido y RSA-PSS.

    - Genera una clave AES-256 aleatoria por mensaje
    - Cifra el mensaje con AES-GCM (nonce aleatorio)
    - Envuelve la clave AES con la clave pública del destinatario (RSA-OAEP)
    - Firma el paquete canónico con la clave privada del emisor (RSA-PSS)
    """
    # Clave simétrica aleatoria por mensaje
    clave_simetrica = os.urandom(32)

    # Cifrado simétrico
    aesgcm = AESGCM(clave_simetrica)
    nonce = os.urandom(12)
    mensaje_cifrado = aesgcm.encrypt(nonce, mensaje.encode("utf-8"), None)

    # Envolver la clave simétrica con RSA-OAEP
    clave_simetrica_cifrada = clave_publica_destinatario.encrypt(
        clave_simetrica,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Construir paquete base (sin firma)
    paquete_sin_firma = {
        "version": 1,
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "clave_simetrica_cifrada": base64.b64encode(clave_simetrica_cifrada).decode("utf-8"),
        "mensaje_cifrado": base64.b64encode(mensaje_cifrado).decode("utf-8"),
    }

    # Firmar paquete canónico
    datos_a_firmar = _canonical_json_bytes(paquete_sin_firma)
    firma = clave_privada_emisor.sign(
        datos_a_firmar,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    paquete = {**paquete_sin_firma, "firma": base64.b64encode(firma).decode("utf-8")}
    return json.dumps(paquete)

def desencriptar_mensaje(paquete_json, clave_privada_destinatario, clave_publica_emisor):
    """Verifica firma y desencripta un mensaje recibido como un paquete JSON."""
    paquete = json.loads(paquete_json)

    firma_b64 = paquete.get("firma")
    if not firma_b64:
        raise ValueError("Paquete sin firma")

    # Reconstruir el objeto canónico sin la firma para verificación
    paquete_sin_firma = {
        "version": paquete.get("version", 1),
        "nonce": paquete["nonce"],
        "clave_simetrica_cifrada": paquete["clave_simetrica_cifrada"],
        "mensaje_cifrado": paquete["mensaje_cifrado"],
    }

    datos_a_verificar = _canonical_json_bytes(paquete_sin_firma)
    firma = base64.b64decode(firma_b64)

    # Verificar firma (autenticidad e integridad)
    clave_publica_emisor.verify(
        firma,
        datos_a_verificar,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # Decodificar campos y desencriptar
    nonce = base64.b64decode(paquete["nonce"])
    clave_simetrica_cifrada = base64.b64decode(paquete["clave_simetrica_cifrada"])
    mensaje_cifrado = base64.b64decode(paquete["mensaje_cifrado"])

    clave_simetrica = clave_privada_destinatario.decrypt(
        clave_simetrica_cifrada,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aesgcm = AESGCM(clave_simetrica)
    mensaje_original_bytes = aesgcm.decrypt(nonce, mensaje_cifrado, None)
    return mensaje_original_bytes.decode("utf-8")

