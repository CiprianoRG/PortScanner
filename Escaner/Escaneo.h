#ifndef ESCANEO_H
#define ESCANEO_H

#include <string>
#include <vector>
// g++ main.cpp Escaneo.cpp -o escaner.exe -lws2_32
// =====================
// Estructura que guarda la información de un puerto
// =====================
struct PortInfo {
    int port;                 // número de puerto
    std::string proto;        // protocolo (ej. "TCP")
    std::string estado;       // "Abierto", "Cerrado", "Filtrado", etc.
    std::string servicio;     // servicio conocido (HTTP, SSH, etc.)
    bool sospechoso;          // para marcarlo después en el análisis
    std::string razon;        // explicación si es sospechoso
};

// =====================
// Declaración de funciones públicas del módulo Escaneo
// =====================

// Función que intenta escanear una lista de puertos en una IP
// ip        -> dirección IP a escanear
// puertos   -> vector con los números de puerto
// timeoutMs -> tiempo de espera por puerto en milisegundos
// Retorna   -> vector con información de cada puerto
std::vector<PortInfo> escanearPuertos(
    const std::string& ip,
    const std::vector<int>& puertos,
    int timeoutMs = 300
);

// Función auxiliar (opcional) para detectar el servicio según el puerto
std::string obtenerServicio(int puerto);

#endif // ESCANEO_H
