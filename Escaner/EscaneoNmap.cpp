#include "EscaneoNmap.h"
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <iostream>

// Implementación de escaneo con Nmap
std::vector<PortInfo> EscaneoNmap::escanear(
    const std::string& ip,
    const std::vector<int>& puertos,
    int timeoutMs
) {
    std::vector<PortInfo> resultados;

    if (puertos.empty()) {
        std::cerr << "No se especificaron puertos para escanear.\n";
        return resultados;
    }

    // Construir rango de puertos como string
    int inicio = puertos.front();
    int fin = puertos.back();
    std::string rango = std::to_string(inicio) + "-" + std::to_string(fin);

    // Ejecutar Nmap y leer salida directamente (sin archivo intermedio)
    //Anteriormente se guardaba el resultado del escaneo en un txt, ahora se lee directamente de la memoria
    std::string comando = "nmap -p " + rango + " " + ip;
    FILE* pipe = popen(comando.c_str(), "r");
    if (!pipe) {
        std::cerr << "No se pudo ejecutar Nmap\n";
        return resultados;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        std::string linea(buffer);

        if (linea.find("/tcp") != std::string::npos) {
            std::stringstream ss(linea);

            int puerto;
            std::string proto_estado, estado, servicio;
            ss >> puerto >> proto_estado >> estado >> servicio;

            PortInfo info;
            info.port = puerto;
            info.proto = "TCP";
            info.estado = (estado == "open") ? "Abierto" :
                        (estado == "filtered") ? "Filtrado" : "Cerrado";
            info.servicio = servicio;
            info.sospechoso = false;
            info.razon = "";

            resultados.push_back(info);
        }
    }

    pclose(pipe);
    return resultados;
}
