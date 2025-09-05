#ifndef ESCANEO_SOCKETS_H
#define ESCANEO_SOCKETS_H

#include "EstrategiaEscaneo.h"
#include <string>
#include <vector>

// g++ main.cpp Escaneo.cpp -o escaner.exe -lws2_32
// ====================

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

// Clase adaptadora para usar tus funciones en el modelo híbrido
class EscaneoSockets : public EstrategiaEscaneo {
public:
    std::vector<PortInfo> escanear(
        const std::string& ip,
        const std::vector<int>& puertos,
        int timeoutMs = 300
    ) override;
};
// Función auxiliar (opcional) para detectar el servicio según el puerto
std::string obtenerServicio(int puerto);

#endif // ESCANEO_H
