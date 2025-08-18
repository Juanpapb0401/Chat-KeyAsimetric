# Taller: Análisis de Tráfico de Red - Comunicación Segura vs Insegura

## Objetivo del Taller

Este taller educativo tiene como propósito **demostrar la importancia del cifrado en las comunicaciones** mediante el análisis comparativo del tráfico de red usando Wireshark. Implementaremos y analizaremos dos versiones de un sistema de chat: una **segura** (con criptografía asimétrica) y otra **insegura** (sin cifrado), para observar las diferencias en el nivel de exposición de la información.

## Contexto Teórico

### ¿Por qué es importante el cifrado?

En el mundo digital actual, la información viaja constantemente a través de redes que pueden ser interceptadas por atacantes. Sin medidas de protección adecuadas, datos sensibles como:

- Conversaciones privadas
- Credenciales de acceso
- Información personal
- Datos empresariales

Pueden ser capturados y leídos por cualquier persona con acceso a la red.

### Criptografía Asimétrica: La Solución

La **criptografía de clave asimétrica** (también conocida como criptografía de clave pública) resuelve este problema mediante:

- **Confidencialidad**: Solo el destinatario puede leer el mensaje
- **Autenticidad**: Se verifica la identidad del remitente
- **Integridad**: Se detecta cualquier modificación del mensaje
- **No repudio**: El emisor no puede negar haber enviado el mensaje

##  Arquitectura del Sistema

### Sistema de Chat Implementado

Hemos desarrollado un sistema de chat punto a punto que utiliza:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Cliente   │◄──►│   Servidor  │◄──►│   Cliente   │
│   (Alice)   │    │   (Relay)   │    │    (Bob)    │
└─────────────┘    └─────────────┘    └─────────────┘
```

**Componentes principales:**

- **Servidor**: Actúa como relay, intercambia claves públicas y retransmite mensajes
- **Cliente**: Genera claves, cifra/descifra mensajes, maneja interfaz de usuario
- **Protocolo**: Framing TCP con longitud-prefijo para comunicación confiable

##  Versión Segura: Implementación Criptográfica

### Modelo de Seguridad

La versión segura implementa un **esquema híbrido** que combina:

1. **RSA-2048** para criptografía asimétrica
2. **AES-256-GCM** para cifrado simétrico
3. **RSA-PSS** para firmas digitales

### Flujo de Comunicación Segura

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as Servidor
    participant B as Bob

    Note over A,B: 1. Generación de Claves
    A->>A: Genera par RSA (privada_A, pública_A)
    B->>B: Genera par RSA (privada_B, pública_B)

    Note over A,B: 2. Intercambio de Claves Públicas
    A->>S: {nombre: "Alice", pública_A}
    B->>S: {nombre: "Bob", pública_B}
    S->>A: {nombre: "Bob", pública_B}
    S->>B: {nombre: "Alice", pública_A}

    Note over A,B: 3. Envío de Mensaje Cifrado
    A->>A: Genera clave_AES aleatoria
    A->>A: Cifra mensaje con AES-GCM
    A->>A: Cifra clave_AES con pública_B (RSA-OAEP)
    A->>A: Firma paquete con privada_A (RSA-PSS)
    A->>S: Paquete cifrado y firmado
    S->>B: Retransmite paquete

    Note over A,B: 4. Verificación y Descifrado
    B->>B: Verifica firma con pública_A
    B->>B: Descifra clave_AES con privada_B
    B->>B: Descifra mensaje con AES-GCM
```

### Características de Seguridad

- **Confidencialidad**: Cada mensaje usa una clave AES-256 única, envuelta con RSA-OAEP
- **Autenticidad**: Firmas RSA-PSS garantizan la identidad del emisor
- **Integridad**: AES-GCM detecta cualquier modificación
- **Persistencia**: Las claves se almacenan localmente para identidad consistente

##  Versión Insegura: Sin Protección

### Propósito Educativo

La versión insegura **deliberadamente omite toda protección criptográfica** para demostrar los riesgos de las comunicaciones sin cifrar.

### Características de la Versión Insegura

- **Sin cifrado**: Todos los mensajes viajan en texto plano
- **Sin firmas**: No hay verificación de autenticidad
- **Sin verificación**: Cualquiera puede leer o modificar mensajes
- **Protocolo visible**: Toda la estructura de comunicación es observable

### Flujo de Comunicación Insegura

```mermaid
sequenceDiagram
    participant A as Alice
    participant S as Servidor
    participant B as Bob
    participant E as Atacante

    A->>S: {nombre: "Alice", modo: "PLAIN_TEXT"}
    B->>S: {nombre: "Bob", modo: "PLAIN_TEXT"}
    S->>A: {nombre: "Bob"}
    S->>B: {nombre: "Alice"}

    Note over A,B: Mensaje completamente visible
    A->>S: {"mensaje_plano": "Hola Bob, tengo información confidencial"}
    Note over E: Atacante intercepta y lee todo
    E->>E: Lee: "Hola Bob, tengo información confidencial"
    S->>B: {"mensaje_plano": "Hola Bob, tengo información confidencial"}
```



