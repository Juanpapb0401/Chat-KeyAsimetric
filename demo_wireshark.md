# Guía de Análisis con Wireshark - Chat Sin Cifrado

Esta guía te ayudará a analizar el tráfico de red del chat sin cifrado usando Wireshark.

## Configuración Inicial

### 1. Preparar el Entorno

```bash
# Terminal 1: Servidor sin cifrado
python servidor_plain.py

# Terminal 2: Cliente Alice
python client_plain.py Alice

# Terminal 3: Cliente Bob
python client_plain.py Bob
```

### 2. Configurar Wireshark

1. **Abrir Wireshark** como administrador
2. **Seleccionar interfaz**: Loopback (127.0.0.1) o "lo" en Linux/macOS
3. **Aplicar filtro**: `tcp.port == 65433`
4. **Iniciar captura**

## Patrones de Tráfico a Observar

### Handshake (Conexión Inicial)

Busca estos paquetes al inicio:

```json
{
  "nombre": "Alice",
  "public_key_pem": "DUMMY_PUBLIC_KEY_FOR_Alice_PLAIN_MODE",
  "mode": "PLAIN_TEXT",
  "encryption": "NONE"
}
```

### Mensajes de Chat

Cada mensaje aparece como JSON legible:

```json
{
  "version": 1,
  "encryption": "NONE",
  "message_type": "PLAIN_TEXT",
  "mensaje_plano": "Hola Bob, este mensaje es completamente visible",
  "timestamp": "a1b2c3d4",
  "dummy_signature": "NO_SIGNATURE_PLAIN_MODE"
}
```

## Filtros Útiles de Wireshark

### Filtros Básicos

```
tcp.port == 65433                          # Todo el tráfico del chat
tcp.port == 65433 and tcp.len > 0         # Solo paquetes con datos
frame contains "mensaje_plano"             # Paquetes con mensajes de chat
frame contains "Alice"                     # Paquetes que mencionan a Alice
```

### Filtros Avanzados

```
tcp.port == 65433 and tcp.stream eq 0     # Solo la primera conexión TCP
tcp.port == 65433 and tcp.stream eq 1     # Solo la segunda conexión TCP
json.value.string contains "Hola"         # Buscar mensajes específicos
```

## Estructura de los Paquetes

### 1. Framing TCP

- **4 bytes**: Longitud del mensaje (uint32 big-endian)
- **N bytes**: Payload JSON en UTF-8

### 2. Contenido JSON

- **Handshake**: nombre, clave dummy, modo
- **Mensajes**: versión, tipo, mensaje en claro, timestamp

### 3. Flujo de Comunicación

1. Cliente → Servidor: Handshake con nombre
2. Servidor → Cliente: Respuesta con datos del otro usuario
3. Cliente ↔ Servidor ↔ Cliente: Retransmisión de mensajes

## Comandos de Debug en el Cliente

```bash
# En el cliente, prueba estos comandos:
/debug          # Muestra información útil para Wireshark
/showkeys       # Muestra las claves dummy
Hola mundo      # Mensaje normal que aparecerá en Wireshark
```


