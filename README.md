# Chat con Criptografía de Clave Asimétrica

Implementa un chat punto a punto (vía servidor relay) usando cifrado híbrido con RSA-OAEP + AES-GCM y firmas digitales RSA-PSS para autenticidad e integridad. El servidor solo retransmite bytes, no conoce el contenido.

## Características de Seguridad

- **Persistencia de Llaves**: Las llaves criptográficas se almacenan localmente en formato base64
- **Verificación de Llaves Existentes**: El sistema verifica si existen llaves antes de generar nuevas
- **Almacenamiento Seguro**: Las llaves se guardan en un directorio `keys/` separado
- **Regeneración de Llaves**: Capacidad de regenerar llaves cuando sea necesario

## Requisitos

- Python 3.10+
- Dependencias en `requirements.txt`

## Instalación

```bash
pip install -r requirements.txt
```

## Ejecución

1. Inicia el servidor:

```bash
python servidor.py
```

2. En dos terminales aparte, inicia dos clientes (ejemplo con nombres Alice y Bob):

```bash
python client.py Alice
python client.py Bob
```

Cuando ambos se conecten, el servidor intercambiará sus claves públicas y podrán chatear.

## Comandos del Cliente

- `/showkeys`: Imprime en consola tu clave privada (PEM, sin cifrar) y tu clave pública (PEM). Úsalo solo con fines educativos.
- `/regenerate`: Regenera nuevas llaves criptográficas y las guarda localmente.
- `/keyinfo`: Muestra información sobre el estado de las llaves almacenadas.
- `/exit`: Cierra el cliente.

## Sistema de Persistencia de Llaves

### Estructura de Archivos
```
keys/
├── Alice_private.key    # Llave privada de Alice en base64
├── Alice_public.key     # Llave pública de Alice en base64
├── Bob_private.key      # Llave privada de Bob en base64
└── Bob_public.key       # Llave pública de Bob en base64
```

### Comportamiento
1. **Primera Ejecución**: Se generan nuevas llaves RSA-2048 y se almacenan en base64
2. **Ejecuciones Posteriores**: Se cargan las llaves existentes desde los archivos
3. **Verificación**: El sistema verifica la integridad de las llaves antes de usarlas
4. **Regeneración**: Comando `/regenerate` permite crear nuevas llaves cuando sea necesario

### Seguridad
- Las llaves se almacenan en formato base64 para mayor compatibilidad
- El directorio `keys/` está excluido del control de versiones (`.gitignore`)
- Las llaves privadas nunca se transmiten por la red
- Solo se intercambian llaves públicas durante el handshake

## Modelo criptográfico

- Cada cliente genera un par RSA (2048 bits) al inicio de la sesión.
- Handshake: el cliente envía `nombre` y su clave pública PEM al servidor; este los intercambia entre los dos clientes conectados.
- Al enviar un mensaje:
  - Se genera una clave simétrica AES-256 aleatoria por mensaje.
  - Se cifra el mensaje con AES-GCM (nonce aleatorio).
  - La clave AES se envuelve con RSA-OAEP usando la clave pública del destinatario.
  - Se firma el paquete (sin firma) con RSA-PSS usando la clave privada del emisor.
- Al recibir un mensaje:
  - Se verifica la firma con la clave pública del emisor (recibida en el handshake).
  - Se desencripta la clave AES con la clave privada del destinatario y luego el mensaje con AES-GCM.

## Notas

- El servidor actual empareja exactamente a dos clientes y retransmite entre ellos.
- Se usa framing de mensajes con longitud-prefijo (uint32 big-endian) para fiabilidad sobre TCP.
- Las llaves se mantienen entre sesiones para mayor comodidad del usuario.
- En caso de corrupción de llaves, use `/regenerate` para crear nuevas.
