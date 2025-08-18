# crypto_utils_plain.py
# Version sin cifrado para análisis de tráfico de red con Wireshark

import os
import json
import base64

class Usuario:
    """
    Representa a un usuario sin criptografía - solo almacena nombres.
    Mantiene la misma interfaz que la versión cifrada para compatibilidad.
    """
    def __init__(self, nombre):
        self.nombre = nombre
        self.clave_privada = None  # No se usa pero se mantiene por compatibilidad
        self.clave_publica = None  # No se usa pero se mantiene por compatibilidad
        self.clave_publica_destinatario = None
        self.nombre_destinatario = "Otro Usuario"
        
        print(f"[INFO] Usuario {nombre} creado (modo sin cifrado)")

    def generar_nuevas_llaves(self):
        """Método dummy - no genera llaves reales."""
        print(f"[INFO] Llaves 'generadas' para {self.nombre} (modo dummy)")

    def guardar_llaves(self):
        """Método dummy - simula guardado de llaves."""
        print(f"[INFO] Llaves de {self.nombre} 'guardadas' (modo dummy)")
        return True

    def cargar_llaves(self):
        """Método dummy - simula carga de llaves."""
        print(f"[INFO] Llaves de {self.nombre} 'cargadas' (modo dummy)")
        return True

    def regenerar_llaves(self):
        """Método dummy - simula regeneración de llaves."""
        print(f"[INFO] Llaves de {self.nombre} 'regeneradas' (modo dummy)")
        return True

    def serializar_clave_publica(self):
        """Devuelve una clave pública dummy en formato PEM."""
        dummy_key = f"-----BEGIN PUBLIC KEY-----\nDUMMY_PUBLIC_KEY_FOR_{self.nombre}_PLAIN_MODE\n-----END PUBLIC KEY-----"
        return dummy_key.encode('utf-8')

    def serializar_clave_privada(self, password: str | None = None):
        """Devuelve una clave privada dummy en formato PEM."""
        dummy_key = f"-----BEGIN PRIVATE KEY-----\nDUMMY_PRIVATE_KEY_FOR_{self.nombre}_PLAIN_MODE\n-----END PRIVATE KEY-----"
        return dummy_key.encode('utf-8')

def cargar_clave_publica(pem_data):
    """Función dummy que simula cargar una clave pública."""
    return "DUMMY_PUBLIC_KEY_OBJECT"

def encriptar_mensaje(mensaje, clave_publica_destinatario, clave_privada_emisor):
    """
    VERSIÓN SIN CIFRADO: Devuelve el mensaje en texto plano dentro de un JSON.
    
    Esta función mantiene la misma interfaz que la versión cifrada pero
    simplemente empaqueta el mensaje en JSON sin aplicar ningún cifrado.
    """
    # Crear un paquete JSON simple con el mensaje en texto plano
    paquete = {
        "version": 1,
        "encryption": "NONE",
        "message_type": "PLAIN_TEXT",
        "mensaje_plano": mensaje,  # Mensaje completamente visible
        "timestamp": str(os.urandom(4).hex()),  # Datos dummy para análisis
        "dummy_signature": "NO_SIGNATURE_PLAIN_MODE"
    }
    
    # Convertir a JSON - esto es lo que viajará por la red SIN CIFRADO
    json_message = json.dumps(paquete, indent=2)  # indent para mejor legibilidad en Wireshark
    
    print(f"[DEBUG PLAIN] Mensaje enviado sin cifrar: {mensaje}")
    return json_message

def desencriptar_mensaje(paquete_json, clave_privada_destinatario, clave_publica_emisor):
    """
    VERSIÓN SIN CIFRADO: Extrae el mensaje en texto plano del JSON.
    
    Esta función mantiene la misma interfaz que la versión cifrada pero
    simplemente extrae el mensaje del JSON sin aplicar ningún descifrado.
    """
    try:
        paquete = json.loads(paquete_json)
        
        # Verificar que es un paquete de la versión sin cifrado
        if paquete.get("encryption") != "NONE":
            raise ValueError("Paquete no es de la versión sin cifrado")
        
        # Extraer el mensaje en texto plano
        mensaje_plano = paquete.get("mensaje_plano", "")
        
        print(f"[DEBUG PLAIN] Mensaje recibido sin cifrar: {mensaje_plano}")
        return mensaje_plano
        
    except json.JSONDecodeError:
        raise ValueError("JSON malformado en mensaje sin cifrar")
    except Exception as e:
        raise ValueError(f"Error al procesar mensaje sin cifrar: {e}")

def _debug_packet_info(paquete_json):
    """Función de utilidad para mostrar información del paquete para debugging."""
    try:
        paquete = json.loads(paquete_json)
        print(f"[PACKET DEBUG] Tipo: {paquete.get('message_type', 'UNKNOWN')}")
        print(f"[PACKET DEBUG] Cifrado: {paquete.get('encryption', 'UNKNOWN')}")
        print(f"[PACKET DEBUG] Tamaño: {len(paquete_json)} bytes")
        return True
    except:
        return False
