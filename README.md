# Proyecto: Escáner de Puertos en C++

## 📌 Descripción general
Este proyecto consiste en el desarrollo de un **escáner de puertos real en C++**, capaz de analizar el estado de los puertos en una dirección IP específica y registrar aquellos que se consideren potencialmente sospechosos.  

El programa está dividido en módulos que gestionan:
- **Escaneo** → implementación híbrida con tres enfoques distintos (Sockets, ASIO, Nmap).
- **Análisis** → evaluación de riesgos, clasificación (bajo, medio, alto, crítico) e identificación de vulnerabilidades comunes.
- **Registro** → almacenamiento de los resultados en un archivo de texto (`Registro.txt`) junto con información de auditoría.


---

## 👥 Integrantes del equipo
- DIEGO AGUAYO FRIAS
- VALERIA ABIGAIL NAVARRO CASAREZ
- ASHLEY KARINA RIOS RODRIGUEZ
- LUIS CIPRIANO RODRIGUEZ GONZALEZ

---

## ⚙️ Instrucciones de compilación y ejecución

### Requisitos
- **Sistema operativo**: Windows / Linux / macOS  
- **Compilador recomendado**: **MSVC** (Microsoft Visual C++), ya que soporta C++17, hilos y funciona bien con ASIO.  
- Alternativas: g++ ≥ 9.0 o clang con soporte para C++17 y `-pthread`.  
- **Librerías utilizadas**:
  - `Winsock2` (para sockets en Windows)  
  - `sys/socket`, `arpa/inet` (para sockets en Linux/macOS)  
  - [ASIO](https://think-async.com/) (standalone, incluida en `include/asio/`)  
  - `Nmap` (opcional, para el escaneo externo)  


### Compilación con MSVC (Windows)
```powershell
cl /std:c++17 /EHsc src\*.cpp /I include /Fe:escaner.exe
```
## Entrada esperada

Dirección IP objetivo (ej. 127.0.0.1)

Puertos (ej. 80,443 o 20-100,8080)

<img width="1483" height="702" alt="image" src="https://github.com/user-attachments/assets/7e8fc709-afea-448f-a845-8ab22a262b26" />



## 🔎 Enfoque técnico del escaneo

El proyecto implementa un **modelo híbrido**, donde el usuario puede elegir entre tres estrategias distintas de escaneo. La motivación de esta decisión fue **aprender y comparar** cómo funcionan los diferentes enfoques y qué ventajas o desventajas tiene cada uno.

### 1. Sockets clásicos (bloqueante)

* **Cómo funciona**:
  Utiliza directamente las APIs de sockets (`Winsock2` en Windows, `sys/socket` en Linux) para intentar establecer conexiones TCP puerto por puerto.
  Mediante `select()` y un tiempo de espera configurable, se determina si un puerto está **abierto**, **cerrado** o **filtrado**.
* **Ventajas**:

  * No depende de librerías externas (solo las estándar del sistema).
  * Es el enfoque más bajo nivel → máximo control sobre los sockets.
* **Desventajas**:

  * Más lento, ya que cada puerto se prueba de forma secuencial.
  * Código más verboso y dependiente del sistema operativo (hay que distinguir entre Windows y Linux).

---

### 2. ASIO (asíncrono)

* **Cómo funciona**:
  Usa la librería [ASIO](https://think-async.com/) para manejar conexiones TCP de manera **asíncrona** (no bloqueante). Esto permite escanear muchos puertos en paralelo, estableciendo timers que evitan que el programa se bloquee esperando respuestas.
* **Ventajas**:

  * Mucho más rápido que los sockets clásicos.
  * Permite manejar múltiples conexiones concurrentes sin necesidad de usar manualmente `threads`.
  * Código más portable y moderno.
* **Desventajas**:

  * Requiere aprender la API de ASIO, que es más compleja.
  * Necesita que el compilador soporte C++17 y hilos.

---

### 3. Nmap (externo)

* **Cómo funciona**:
  Se ejecuta el comando `nmap` desde el programa (`system()` o `popen()`), se redirige la salida a un archivo temporal o a un pipe, y luego se analiza línea por línea para extraer información de puertos y servicios.
* **Ventajas**:

  * Nmap es una herramienta **muy madura y poderosa**, con soporte para múltiples protocolos, detección de servicios, fingerprinting, etc.
  * El esfuerzo de programación es mucho menor, porque Nmap hace casi todo el trabajo.
* **Desventajas**:

  * Dependencia externa → es necesario que Nmap esté instalado en el sistema.
  * Menor control sobre el proceso de escaneo (se depende de cómo Nmap entrega los datos).
  * Más difícil integrarlo en proyectos que necesiten ser autónomos.

**Conclusión**: se decidió mantener los tres enfoques para tener un programa **flexible y educativo**, que muestre distintas técnicas y permita experimentar con cada una.

---

## 🧩 Estructura general del programa

El proyecto está **modularizado** para facilitar su comprensión, mantenimiento y ampliación. Cada módulo cumple una función clara:

* **`main.cpp`** → Punto de entrada. Se encarga de pedir la IP y puertos, elegir la estrategia de escaneo y orquestar el análisis y el registro.
* **`EstrategiaEscaneo.h`** → Interfaz base que define el método `escanear()`. Todas las estrategias (Sockets, ASIO, Nmap) heredan de aquí, lo que permite intercambiarlas sin cambiar el resto del programa (**patrón de diseño Strategy**).
* **`EscaneoSockets.cpp/.h`** → Implementación del escaneo usando sockets clásicos.
* **`EscaneoAsio.cpp/.h`** → Implementación del escaneo asíncrono usando ASIO.
* **`EscaneoNmap.cpp/.h`** → Implementación del escaneo externo usando Nmap.
* **`Analisis.cpp/.h`** → Contiene la lógica de análisis de los resultados: clasificación de riesgos, detección de vulnerabilidades comunes, puntuación y etiquetas de riesgo.
* **`Registro.cpp/.h`** → Módulo encargado de guardar en `Registro.txt` la información del escaneo (IP, fecha, resultados, vulnerabilidades).
* **`Utilidades.cpp/.h`** → Funciones auxiliares, como validación de IP, parseo de rangos de puertos, detección de servicios por número de puerto, etc.
* **`include/asio/`** → Carpeta con la librería ASIO standalone, para que el proyecto sea autocontenido.
---

## 🚨 Criterios para puertos sospechosos

Los puertos se analizan con base en:

- Puertos conocidos de malware/backdoors (ej. 4444, 31337, 12345).

- Puertos de administración expuestos (ej. SSH, RDP, Telnet, SQL).

- Puertos altos inusuales que no deberían estar abiertos.

- Bloques consecutivos de puertos abiertos (indicador de un posible escaneo malicioso).

- Servicios sin cifrado (HTTP, Telnet, FTP, POP3, IMAP).

Cada puerto abierto recibe un nivel de riesgo:

- CRÍTICO 🔴

- ALTO 🟠

- MEDIO 🟡

- BAJO 🟢

- DESCONOCIDO ⚪

## 📄 Salida generada

El archivo Registro.txt incluye:

- Fecha y hora del escaneo.

- Dirección IP objetivo.

- Lista completa de puertos con su estado (Abierto, Cerrado, Filtrado).

- Clasificación de riesgo por cada puerto abierto.

- Vulnerabilidades identificadas (si aplican).

Ejemplo:
```cmd
Resultados del escaneo para la IP: 127.0.0.1

Puerto 80 (HTTP): Abierto - Riesgo BAJO
Puerto 135 (Desconocido): Abierto - Riesgo MEDIO - Vulnerabilidad: RPC expuesto
Puerto 443 (HTTPS): Abierto - Riesgo BAJO
Puerto 23 (Telnet): Cerrado

```
