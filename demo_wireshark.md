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

## Experimentos Recomendados

### Experimento 1: Comparar Tráfico Cifrado vs Sin Cifrar

1. Ejecuta el chat cifrado (puerto 65432) y captura tráfico
2. Ejecuta el chat sin cifrado (puerto 65433) y captura tráfico
3. Compara los paquetes - en el cifrado solo verás bytes ilegibles

### Experimento 2: Seguir una Conversación

1. En Wireshark: clic derecho en un paquete → "Follow TCP Stream"
2. Verás toda la conversación entre Alice y Bob en texto plano
3. Nota cómo se estructura el protocolo con longitudes-prefijo

### Experimento 3: Timing de Mensajes

1. Habilita la columna "Time" en Wireshark
2. Envía mensajes a intervalos conocidos
3. Analiza la latencia de red y retransmisión del servidor

## Comandos de Debug en el Cliente

```bash
# En el cliente, prueba estos comandos:
/debug          # Muestra información útil para Wireshark
/showkeys       # Muestra las claves dummy
Hola mundo      # Mensaje normal que aparecerá en Wireshark
```

## Qué Buscar en el Análisis

### Seguridad (Versión Sin Cifrado)

- ✅ **Visible**: Nombres de usuarios, mensajes completos, estructura de protocolo
- ✅ **Interceptable**: Cualquier atacante puede leer todo el tráfico
- ❌ **Sin protección**: No hay cifrado, firmas ni autenticación

### Protocolo de Red

- ✅ **Framing**: Longitud-prefijo para mensajes completos
- ✅ **JSON**: Estructura clara y extensible
- ✅ **TCP**: Transporte confiable

### Comparación Educativa

Usa este análisis para:

1. **Entender la necesidad del cifrado**: Ver lo vulnerable que es el texto plano
2. **Comprender protocolos**: Observar cómo se estructura la comunicación
3. **Apreciar la criptografía**: Contrastar con la versión cifrada donde nada es legible

## Exportar Datos para Reportes

### Exportar Paquetes

```
File → Export Packet Dissections → As Plain Text
```

### Exportar Conversaciones

```
Statistics → Conversations → TCP → Copy → All CSV
```

### Capturar Pantallas

1. Filtra por una conversación específica
2. Follow TCP Stream para ver el flujo completo
3. Captura pantallas del contenido JSON legible

---

