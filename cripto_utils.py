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
        self.clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.clave_publica = self.clave_privada.public_key()
        self.clave_publica_destinatario = None
        self.nombre_destinatario = "Otro Usuario"

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

