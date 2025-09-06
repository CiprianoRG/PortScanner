# Proyecto: Escáner de Puertos en C++

## 📌 Descripción general
Este proyecto consiste en el desarrollo de un **escáner de puertos real en C++**, capaz de analizar el estado de los puertos en una dirección IP específica y registrar aquellos que se consideren potencialmente sospechosos.  

El programa está dividido en módulos que gestionan:
- **Escaneo** → implementación híbrida con tres enfoques distintos (Sockets, ASIO, Nmap).
- **Análisis** → evaluación de riesgos, clasificación (bajo, medio, alto, crítico) e identificación de vulnerabilidades comunes.
- **Registro** → almacenamiento de los resultados en un archivo de texto (`Registro.txt`) junto con información de auditoría.


---

## 👥 Integrantes del equipo
- Nombre 1 — [correo o GitHub]  
- Nombre 2 — [correo o GitHub]  
- Nombre 3 — [opcional]  
- Nombre 4 — [opcional]  

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

Este proyecto implementa un modelo híbrido que permite elegir entre diferentes estrategias:

Sockets clásicos: se establece una conexión TCP directa para determinar si un puerto está abierto, cerrado o filtrado.

ASIO: se utiliza la librería ASIO para realizar escaneos asíncronos y más rápidos.

Nmap: se ejecuta el comando nmap mediante system() o popen() y se analiza la salida generada.

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
